#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CONFIG_FILE        "./applist.conf"
#define CONFIG_RELOAD_TIME 10
#define PROC_CACHE_TIME    10
#define MAX_PKG_LEN        128
#define MAX_THREAD_LEN     32

typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    cpu_set_t cpus;
} AffinityRule;

typedef struct {
    pid_t tid;
    char name[MAX_THREAD_LEN];
    cpu_set_t cpus;
} ThreadInfo;

typedef struct {
    pid_t pid;
    char pkg[MAX_PKG_LEN];
    cpu_set_t base_cpus;
    ThreadInfo* threads;
    size_t num_threads;
    AffinityRule** thread_rules;
    size_t num_thread_rules;
} ProcessInfo;

typedef struct {
    cpu_set_t present_cpus;
    bool cpuset_enabled;
    char present_str[256];
} CpuTopology;

typedef struct {
    AffinityRule* rules;
    size_t num_rules;
    time_t mtime;
    CpuTopology topo;
    char** pkgs;
    size_t num_pkgs;
} AppConfig;

typedef struct {
    ProcessInfo* procs;
    size_t num_procs;
    time_t last_update;
} ProcCache;

static inline void* xrealloc(void* ptr, size_t size) {
    void* p = realloc(ptr, size);
    if (!p && size != 0) {
        return NULL;
    }
    return p;
}

static char* strtrim(char* s) {
    char* end;
    while (isspace(*s)) s++;
    if (*s == 0) return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) end--;
    *(end + 1) = 0;
    return s;
}

static bool is_screen_on(void) {
    bool has_backlight = false;
    int dir_fd = open("/sys/class/backlight", O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) {
        DIR* dir = fdopendir(dir_fd);
        if (dir) {
            struct dirent* ent;
            while ((ent = readdir(dir))) {
                if (ent->d_name[0] == '.') continue;

                int bl_fd = openat(dir_fd, ent->d_name, O_RDONLY | O_DIRECTORY);
                if (bl_fd < 0) continue;

                int val_fd = openat(bl_fd, "brightness", O_RDONLY);
                close(bl_fd);

                if (val_fd >= 0) {
                    has_backlight = true;
                    char buf[32] = {0};
                    ssize_t n = read(val_fd, buf, sizeof(buf) - 1);
                    close(val_fd);
                    if (n > 0) {
                        long value = strtol(buf, NULL, 10);
                        if (value > 0) {
                            closedir(dir);
                            return true;
                        }
                    }
                }
            }
            closedir(dir);
        } else {
            close(dir_fd);
        }
    }

    if (has_backlight) return false;
    FILE* fp = popen("dumpsys deviceidle get screen 2>/dev/null", "r");
    if (fp) {
        char buf[32] = {0};
        size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
        buf[n] = '\0';
        pclose(fp);
        if (strstr(buf, "false") == NULL) {
            return true;
        } else {
            return false;
        }
    }
    return true;
}

static void parse_cpu_ranges(const char* spec, cpu_set_t* set, const cpu_set_t* present) {
    if (!spec || !set) return;
    char* copy = strdup(spec);
    if (!copy) return;
    char* s = copy;
    char* e;

    while (s) {
        e = strchr(s, ',');
        if (e) *e++ = '\0';

        unsigned a, b;
        if (sscanf(s, "%u-%u", &a, &b) == 2) {
            if (a > b) { unsigned t = a; a = b; b = t; }
        } else if (sscanf(s, "%u", &a) == 1) {
            b = a;
        } else {
            s = e;
            continue;
        }

        for (; a <= b && a < CPU_SETSIZE; a++) {
            if (present && !CPU_ISSET(a, present)) continue;
            CPU_SET(a, set);
        }
        s = e;
    }
    free(copy);
}

static CpuTopology init_cpu_topo(void) {
    CpuTopology topo = { .cpuset_enabled = false };
    CPU_ZERO(&topo.present_cpus);
    memset(topo.present_str, 0, sizeof(topo.present_str));

    int fd = open("/sys/devices/system/cpu/present", O_RDONLY);
    if (fd != -1) {
        char buf[64] = {0};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            char* p = strtrim(buf);
            char* end = strchr(p, '\n');
            if (end) *end = '\0';
            strncpy(topo.present_str, p, sizeof(topo.present_str)-1);
            topo.present_str[sizeof(topo.present_str)-1] = '\0';
            parse_cpu_ranges(topo.present_str, &topo.present_cpus, NULL);
        }
        close(fd);
    }

    if (access("/dev/cpuset", F_OK) != 0) {
        return topo;
    }
    const char* cpuset_dir = "/dev/cpuset/AppOpt";
    if (mkdir(cpuset_dir, 0755) != 0) {
        struct stat st;
        if (stat(cpuset_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            return topo;
        }
    }

    chmod(cpuset_dir, 0755);
    chown(cpuset_dir, 0, 0);

    int cpus_fd = open("/dev/cpuset/AppOpt/cpus", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (cpus_fd == -1) {
        return topo;
    }
    if (dprintf(cpus_fd, "%s", topo.present_str) < 0) {
        close(cpus_fd);
        return topo;
    }
    close(cpus_fd);

    int mems_fd = open("/dev/cpuset/AppOpt/mems", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (mems_fd == -1) {
        return topo;
    }
    if (write(mems_fd, "0", 1) != 1) {
        close(mems_fd);
        return topo;
    }
    close(mems_fd);
    topo.cpuset_enabled = true;

    return topo;
}

static bool load_config(AppConfig* cfg) {
    struct stat st;
    if (stat(CONFIG_FILE, &st) != 0) {
        FILE* fp = fopen(CONFIG_FILE, "w");
        if (!fp) return false;
        fclose(fp);
        return false;
    }

    if (st.st_mtime <= cfg->mtime) return false;

    FILE* fp = fopen(CONFIG_FILE, "r");
    if (!fp) return false;

    AffinityRule* new_rules = NULL;
    size_t count = 0;
    char line[256];
    char** new_pkgs = NULL;
    size_t pkgs_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        char* p = strtrim(line);
        if (*p == '#' || *p == 0) continue;

        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq++ = 0;

        char* br = strchr(p, '{');
        char* thread = "";
        if (br) {
            *br++ = 0;
            char* eb = strchr(br, '}');
            if (!eb) continue;
            *eb = 0;
            thread = strtrim(br);
        }

        char* pkg = strtrim(p);
        char* cpus = strtrim(eq);
        if (strlen(pkg) >= MAX_PKG_LEN || strlen(thread) >= MAX_THREAD_LEN)
            continue;

        AffinityRule rule = {0};
        strncpy(rule.pkg, pkg, sizeof(rule.pkg) - 1);
        rule.pkg[sizeof(rule.pkg)-1] = '\0';
        strncpy(rule.thread, thread, sizeof(rule.thread) - 1);
        rule.thread[sizeof(rule.thread)-1] = '\0';
        parse_cpu_ranges(cpus, &rule.cpus, &cfg->topo.present_cpus);

        AffinityRule* tmp = xrealloc(new_rules, (count + 1) * sizeof(AffinityRule));
        if (!tmp) goto error;
        new_rules = tmp;
        new_rules[count++] = rule;
    }

    if (count == 0) {
        free(new_rules);
        fclose(fp);
        return false;
    }

    for (size_t i = 0; i < count; i++) {
        const char* current_pkg = new_rules[i].pkg;
        bool exists = false;
        for (size_t j = 0; j < pkgs_count; j++) {
            if (strcmp(current_pkg, new_pkgs[j]) == 0) {
                exists = true;
                break;
            }
        }
        if (exists) continue;

        char** tmp = xrealloc(new_pkgs, (pkgs_count + 1) * sizeof(char*));
        if (!tmp) goto error;
        new_pkgs = tmp;

        new_pkgs[pkgs_count] = strdup(current_pkg);
        if (!new_pkgs[pkgs_count]) goto error;
        pkgs_count++;
    }

    if (cfg->rules) free(cfg->rules);
    cfg->rules = new_rules;
    cfg->num_rules = count;

    if (cfg->pkgs) {
        for (size_t i = 0; i < cfg->num_pkgs; i++) free(cfg->pkgs[i]);
        free(cfg->pkgs);
    }
    cfg->pkgs = new_pkgs;
    cfg->num_pkgs = pkgs_count;

    cfg->mtime = st.st_mtime;
    fclose(fp);
    return true;

error:
    free(new_rules);
    if (new_pkgs) {
        for (size_t i = 0; i < pkgs_count; i++) free(new_pkgs[i]);
        free(new_pkgs);
    }
    fclose(fp);
    return false;
}

static ProcCache* update_proc_cache(ProcCache* cache, const AppConfig* cfg) {
    time_t now = time(NULL);
    if (now - cache->last_update < PROC_CACHE_TIME) return cache;

    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return cache;

    ProcessInfo* new_procs = NULL;
    size_t count = 0;
    int proc_fd = dirfd(proc_dir);
    struct dirent* ent;

    while ((ent = readdir(proc_dir))) {
        if (ent->d_type != DT_DIR || !isdigit(ent->d_name[0]))
            continue;

        pid_t pid = atoi(ent->d_name);
        char cmd[MAX_PKG_LEN] = {0};

        int pid_fd = openat(proc_fd, ent->d_name, O_RDONLY | O_DIRECTORY);
        if (pid_fd == -1) continue;

        int cmd_fd = openat(pid_fd, "cmdline", O_RDONLY);
        if (cmd_fd == -1) {
            close(pid_fd);
            continue;
        }

        ssize_t n = read(cmd_fd, cmd, sizeof(cmd) - 1);
        close(cmd_fd);
        if (n <= 0) {
            close(pid_fd);
            continue;
        }

        cmd[n] = '\0';
        char* name = strrchr(cmd, '/');
        name = name ? name + 1 : cmd;

        bool found_pkg = false;
        for (size_t j = 0; j < cfg->num_pkgs; j++) {
            if (strcmp(name, cfg->pkgs[j]) == 0) {
                found_pkg = true;
                break;
            }
        }
        if (!found_pkg) {
            close(pid_fd);
            continue;
        }

        ProcessInfo proc = {0};
        proc.pid = pid;
        strncpy(proc.pkg, name, sizeof(proc.pkg) - 1);
        proc.pkg[sizeof(proc.pkg)-1] = '\0';
        CPU_ZERO(&proc.base_cpus);

        proc.thread_rules = NULL;
        proc.num_thread_rules = 0;

        for (size_t i = 0; i < cfg->num_rules; i++) {
            const AffinityRule* rule = &cfg->rules[i];
            if (strcmp(rule->pkg, proc.pkg) != 0) continue;

            if (rule->thread[0]) {
                AffinityRule** tmp = xrealloc(proc.thread_rules,
                    (proc.num_thread_rules + 1) * sizeof(AffinityRule*));
                if (!tmp) continue;
                proc.thread_rules = tmp;
                proc.thread_rules[proc.num_thread_rules++] = (AffinityRule*)rule;
            } else {
                CPU_OR(&proc.base_cpus, &proc.base_cpus, &rule->cpus);
            }
        }

        if (proc.num_thread_rules == 0 && CPU_COUNT(&proc.base_cpus) == 0) {
            close(pid_fd);
            free(proc.thread_rules);
            continue;
        }

        int task_fd = openat(pid_fd, "task", O_RDONLY | O_DIRECTORY);
        close(pid_fd);

        if (task_fd == -1) {
            free(proc.thread_rules);
            continue;
        }

        DIR* task_dir = fdopendir(task_fd);
        if (!task_dir) {
            close(task_fd);
            free(proc.thread_rules);
            continue;
        }

        ThreadInfo* threads = NULL;
        size_t tcount = 0;
        struct dirent* tent;
        while ((tent = readdir(task_dir))) {
            if (tent->d_type != DT_DIR || !isdigit(tent->d_name[0]))
                continue;

            pid_t tid = atoi(tent->d_name);
            char tname[MAX_THREAD_LEN] = {0};

            char comm_path[64];
            snprintf(comm_path, sizeof(comm_path), "%s/comm", tent->d_name);
            int comm_fd = openat(task_fd, comm_path, O_RDONLY);
            if (comm_fd == -1) continue;

            ssize_t n = read(comm_fd, tname, sizeof(tname) - 1);
            close(comm_fd);
            if (n <= 0) continue;

            tname[n] = '\0';
            strtrim(tname);

            cpu_set_t mask;
            CPU_ZERO(&mask);
            for (size_t i = 0; i < proc.num_thread_rules; i++) {
                if (fnmatch(proc.thread_rules[i]->thread, tname, FNM_NOESCAPE) == 0) {
                    CPU_OR(&mask, &mask, &proc.thread_rules[i]->cpus);
                }
            }

            ThreadInfo ti = {
                .tid = tid,
                .cpus = CPU_COUNT(&mask) ? mask : proc.base_cpus
            };
            strncpy(ti.name, tname, sizeof(ti.name) - 1);
            ti.name[sizeof(ti.name)-1] = '\0';

            ThreadInfo* tmp = xrealloc(threads, (tcount + 1) * sizeof(ThreadInfo));
            if (!tmp) goto thread_error;
            threads = tmp;
            threads[tcount++] = ti;
        }

        proc.threads = threads;
        proc.num_threads = tcount;

        ProcessInfo* tmp = xrealloc(new_procs, (count + 1) * sizeof(ProcessInfo));
        if (!tmp) {
            free(threads);
            free(proc.thread_rules);
            closedir(task_dir);
            continue;
        }
        new_procs = tmp;
        new_procs[count++] = proc;
        closedir(task_dir);
        continue;

thread_error:
        free(threads);
        free(proc.thread_rules);
        closedir(task_dir);
    }
    closedir(proc_dir);

    if (cache->procs) {
        for (size_t i = 0; i < cache->num_procs; i++) {
            free(cache->procs[i].threads);
            free(cache->procs[i].thread_rules);
        }
        free(cache->procs);
    }

    cache->procs = new_procs;
    cache->num_procs = count;
    cache->last_update = now;
    return cache;
}

static bool apply_affinity(const ProcessInfo* proc, const CpuTopology* topo) {
    bool applied = false;

    for (size_t i = 0; i < proc->num_threads; i++) {
        const ThreadInfo* ti = &proc->threads[i];
        cpu_set_t curr;
        CPU_ZERO(&curr);

        if (sched_getaffinity(ti->tid, sizeof(curr), &curr) == -1)
            continue;

        if (!CPU_EQUAL(&ti->cpus, &curr)) {
            if (topo->cpuset_enabled) {
                int fd = open("/dev/cpuset/AppOpt/tasks", O_WRONLY | O_APPEND);
                if (fd != -1) {
                    dprintf(fd, "%d\n", ti->tid);
                    close(fd);
                }
            }
            if (sched_setaffinity(ti->tid, sizeof(ti->cpus), &ti->cpus) == 0) {
                applied = true;
            }
        }
    }
    return applied;
}

int main(void) {
    AppConfig config = { .topo = init_cpu_topo() };
    ProcCache cache = {0};
    time_t last_config_check = 0;
    time_t last_affinity_time = 0;

    for (;;) {
        if (!is_screen_on()) {
            nanosleep(&(struct timespec){12, 0}, NULL);
            cache.last_update = 0;
            continue;
        }

        const time_t now = time(NULL);
        if (now - last_config_check >= CONFIG_RELOAD_TIME) {
            if (load_config(&config)) {
                cache.last_update = 0;
            }
            last_config_check = now;
        }

        update_proc_cache(&cache, &config);

        bool applied = false;
        for (size_t i = 0; i < cache.num_procs; i++) {
            applied |= apply_affinity(&cache.procs[i], &config.topo);
        }
        if (applied) last_affinity_time = now;

        struct timespec delay;
        if (now - last_affinity_time <= 5) {
            delay.tv_sec = 0;
            delay.tv_nsec = 500000000;
        } else {
            delay.tv_sec = 3;
            delay.tv_nsec = 0;
        }
        nanosleep(&delay, NULL);
    }
    return 0;
}