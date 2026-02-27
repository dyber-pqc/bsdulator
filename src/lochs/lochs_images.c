/*
 * Lochs Image Registry and Management
 * 
 * Handles pulling, storing, and managing FreeBSD jail images.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

#include "bsdulator/lochs.h"

/* Registry and storage paths */
#define LOCHS_IMAGES_DIR    "/var/lib/lochs/images"
#define LOCHS_CACHE_DIR     "/var/lib/lochs/cache"

/* GitHub release base URL */
#define DYBER_IMAGES_URL    "https://github.com/dyber-pqc/lochs-images/releases/download"
#define FREEBSD_MIRROR_URL  "https://download.freebsd.org/releases/amd64/amd64"

/* Known official images with their download URLs */
typedef struct {
    const char *name;
    const char *tag;
    const char *url;
    const char *description;
    size_t size_mb;
} lochs_official_image_t;

static lochs_official_image_t official_images[] = {
    /*
     * FreeBSD 15.x
     */
    {
        "freebsd", "15",
        FREEBSD_MIRROR_URL "/15.0-RELEASE/base.txz",
        "FreeBSD 15.0-RELEASE base system",
        180
    },
    {
        "freebsd", "15.0",
        FREEBSD_MIRROR_URL "/15.0-RELEASE/base.txz",
        "FreeBSD 15.0-RELEASE base system",
        180
    },
    {
        "freebsd", "15-minimal",
        DYBER_IMAGES_URL "/v15.0/freebsd-15.0-minimal.txz",
        "Minimal FreeBSD 15.0 (stripped)",
        50
    },
    {
        "freebsd", "15.0-minimal",
        DYBER_IMAGES_URL "/v15.0/freebsd-15.0-minimal.txz",
        "Minimal FreeBSD 15.0 (stripped)",
        50
    },
    {
        "freebsd", "15-rescue",
        DYBER_IMAGES_URL "/v15.0/freebsd-15.0-rescue.txz",
        "FreeBSD 15.0 rescue environment",
        15
    },
    
    /*
     * FreeBSD 14.x
     */
    {
        "freebsd", "14",
        FREEBSD_MIRROR_URL "/14.3-RELEASE/base.txz",
        "FreeBSD 14.3-RELEASE base system",
        180
    },
    {
        "freebsd", "14.3",
        FREEBSD_MIRROR_URL "/14.3-RELEASE/base.txz",
        "FreeBSD 14.3-RELEASE base system",
        180
    },
    {
        "freebsd", "14-minimal",
        DYBER_IMAGES_URL "/v14.3/freebsd-14.3-minimal.txz",
        "Minimal FreeBSD 14.3 (stripped)",
        50
    },

    /*
     * FreeBSD 13.x
     */
    {
        "freebsd", "13",
        FREEBSD_MIRROR_URL "/13.5-RELEASE/base.txz",
        "FreeBSD 13.5-RELEASE base system",
        170
    },
    {
        "freebsd", "13.5",
        FREEBSD_MIRROR_URL "/13.5-RELEASE/base.txz",
        "FreeBSD 13.5-RELEASE base system",
        170
    },
    
    /*
     * Rescue image (version-independent)
     */
    {
        "freebsd", "rescue",
        DYBER_IMAGES_URL "/v15.0/freebsd-15.0-rescue.txz",
        "FreeBSD rescue/recovery environment",
        15
    },
    
    {NULL, NULL, NULL, NULL, 0}
};

/* Image entry stored locally */
typedef struct {
    char repository[64];
    char tag[32];
    char id[65];
    char path[512];
    size_t size;
    time_t created;
    time_t pulled;
} lochs_image_t;

/* Local image database */
static lochs_image_t local_images[128];
static int local_image_count = 0;

#define IMAGE_DB_FILE "/var/lib/lochs/images.dat"
#define IMAGE_DB_MAGIC 0x4C494D47  /* 'LIMG' */

/* Safe string copy helper */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t len = strlen(src);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/*
 * Ensure directories exist
 */
static int ensure_dirs(void) {
    mkdir("/var/lib/lochs", 0755);
    mkdir(LOCHS_IMAGES_DIR, 0755);
    mkdir(LOCHS_CACHE_DIR, 0755);
    return 0;
}

/*
 * Generate a simple hash for image ID
 */
static void generate_image_id(const char *repo, const char *tag, char *out) {
    unsigned long hash = 5381;
    const char *str = repo;
    while (*str) hash = ((hash << 5) + hash) + (unsigned char)*str++;
    str = tag;
    while (*str) hash = ((hash << 5) + hash) + (unsigned char)*str++;
    hash ^= (unsigned long)time(NULL);
    snprintf(out, 13, "%012lx", hash & 0xFFFFFFFFFFFFUL);
}

/*
 * Load image database
 */
int lochs_images_load(void) {
    FILE *f = fopen(IMAGE_DB_FILE, "rb");
    if (!f) return 0;
    
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, f) != 1 || magic != IMAGE_DB_MAGIC) {
        fclose(f);
        return -1;
    }
    
    if (fread(&local_image_count, sizeof(local_image_count), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    
    if (local_image_count > 128) local_image_count = 128;
    
    size_t r = fread(local_images, sizeof(lochs_image_t), (size_t)local_image_count, f);
    fclose(f);
    
    return (r == (size_t)local_image_count) ? 0 : -1;
}

/*
 * Save image database
 */
int lochs_images_save(void) {
    ensure_dirs();
    
    FILE *f = fopen(IMAGE_DB_FILE, "wb");
    if (!f) return -1;
    
    uint32_t magic = IMAGE_DB_MAGIC;
    fwrite(&magic, sizeof(magic), 1, f);
    fwrite(&local_image_count, sizeof(local_image_count), 1, f);
    fwrite(local_images, sizeof(lochs_image_t), (size_t)local_image_count, f);
    fclose(f);
    
    return 0;
}

/*
 * Parse image name into repository and tag
 */
static void parse_image_name(const char *name, char *repo, size_t repo_size, 
                             char *tag, size_t tag_size) {
    const char *colon = strchr(name, ':');
    if (colon) {
        size_t repo_len = (size_t)(colon - name);
        if (repo_len >= repo_size) repo_len = repo_size - 1;
        memcpy(repo, name, repo_len);
        repo[repo_len] = '\0';
        safe_strcpy(tag, colon + 1, tag_size);
    } else {
        safe_strcpy(repo, name, repo_size);
        safe_strcpy(tag, "15", tag_size);  /* Default to latest stable */
    }
}

/*
 * Find local image
 */
static lochs_image_t *find_local_image(const char *repo, const char *tag) {
    for (int i = 0; i < local_image_count; i++) {
        if (strcmp(local_images[i].repository, repo) == 0 &&
            strcmp(local_images[i].tag, tag) == 0) {
            return &local_images[i];
        }
    }
    return NULL;
}

/*
 * Find official image info
 */
static lochs_official_image_t *find_official_image(const char *repo, const char *tag) {
    for (int i = 0; official_images[i].name != NULL; i++) {
        if (strcmp(official_images[i].name, repo) == 0 &&
            strcmp(official_images[i].tag, tag) == 0) {
            return &official_images[i];
        }
    }
    return NULL;
}

/*
 * Download file with progress
 */
static int download_file(const char *url, const char *dest) {
    char cmd[4096];
    
    int n = snprintf(cmd, sizeof(cmd),
        "curl -L --progress-bar -o '%s' '%s' 2>&1 || "
        "wget --progress=bar:force -O '%s' '%s' 2>&1",
        dest, url, dest, url);
    
    if (n >= (int)sizeof(cmd)) {
        fprintf(stderr, "Error: URL too long\n");
        return -1;
    }
    
    printf("Downloading from %s\n", url);
    int ret = system(cmd);
    
    if (ret != 0) {
        fprintf(stderr, "Download failed\n");
        unlink(dest);
        return -1;
    }

    /* Validate download - check it's not an HTML error page */
    FILE *check = fopen(dest, "rb");
    if (check) {
        char header[16];
        size_t nread = fread(header, 1, sizeof(header), check);
        fclose(check);
        if (nread >= 5 && (memcmp(header, "<html", 5) == 0 ||
                           memcmp(header, "<!DOC", 5) == 0 ||
                           memcmp(header, "<HTML", 5) == 0)) {
            fprintf(stderr, "Error: Download returned an HTML page instead of an archive.\n");
            fprintf(stderr, "The mirror URL may be outdated or the release was removed.\n");
            unlink(dest);
            return -1;
        }
    }

    return 0;
}

/*
 * Extract tarball to directory
 */
static int extract_tarball(const char *tarball, const char *dest) {
    char cmd[4096];
    int n;
    
    mkdir(dest, 0755);
    
    /* --warning=no-unknown-keyword suppresses FreeBSD SCHILY.fflags noise */
    if (strstr(tarball, ".txz") || strstr(tarball, ".tar.xz")) {
        n = snprintf(cmd, sizeof(cmd),
            "tar --warning=no-unknown-keyword -xJf '%s' -C '%s'", tarball, dest);
    } else if (strstr(tarball, ".tgz") || strstr(tarball, ".tar.gz")) {
        n = snprintf(cmd, sizeof(cmd),
            "tar --warning=no-unknown-keyword -xzf '%s' -C '%s'", tarball, dest);
    } else {
        n = snprintf(cmd, sizeof(cmd),
            "tar --warning=no-unknown-keyword -xf '%s' -C '%s'", tarball, dest);
    }
    
    if (n >= (int)sizeof(cmd)) {
        fprintf(stderr, "Error: Path too long\n");
        return -1;
    }
    
    printf("Extracting to %s...\n", dest);
    int ret = system(cmd);

    return (ret == 0) ? 0 : -1;
}

/*
 * Strip a FreeBSD image to reduce size (~830MB -> ~300MB).
 * Removes docs, debug symbols, includes, games, etc.
 */
static void strip_image(const char *path) {
    char cmd[2048];
    int r;

    printf("Stripping image (removing docs, debug symbols, etc.)...\n");

    static const char *strip_dirs[] = {
        "usr/share/doc", "usr/share/man", "usr/share/info",
        "usr/share/examples", "usr/lib/debug",
        "usr/include/c++", "usr/share/nls",
        "usr/games", "usr/share/games",
        "usr/share/zoneinfo/posix", "usr/share/zoneinfo/right",
        NULL
    };

    for (int i = 0; strip_dirs[i]; i++) {
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'/%s 2>/dev/null", path, strip_dirs[i]);
        r = system(cmd);
        (void)r;
    }

    /* Clean caches */
    snprintf(cmd, sizeof(cmd),
        "rm -rf '%s'/var/db/pkg/* '%s'/var/cache/* '%s'/tmp/* 2>/dev/null",
        path, path, path);
    r = system(cmd);
    (void)r;

    /* Remove non-English locales */
    snprintf(cmd, sizeof(cmd),
        "find '%s'/usr/share/locale -mindepth 1 -maxdepth 1 -type d "
        "! -name 'C' ! -name 'en_US*' -exec rm -rf {} + 2>/dev/null; true",
        path);
    r = system(cmd);
    (void)r;
}

/*
 * Get directory size in bytes
 */
static size_t get_dir_size(const char *path) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "du -sb '%s' 2>/dev/null | cut -f1", path);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;
    
    size_t size = 0;
    if (fscanf(fp, "%zu", &size) != 1) {
        size = 0;
    }
    pclose(fp);
    
    return size;
}

/*
 * Pull an image from registry
 */
int lochs_image_pull(const char *image_name) {
    char repo[64], tag[32];
    parse_image_name(image_name, repo, sizeof(repo), tag, sizeof(tag));
    
    printf("Pulling %s:%s...\n", repo, tag);
    
    /* Check if already exists locally */
    lochs_image_t *existing = find_local_image(repo, tag);
    if (existing) {
        printf("Image %s:%s already exists locally\n", repo, tag);
        printf("  Path: %s\n", existing->path);
        printf("  Size: %zu MB\n", existing->size / (1024*1024));
        return 0;
    }
    
    /* Find in official images */
    lochs_official_image_t *official = find_official_image(repo, tag);
    
    if (!official) {
        fprintf(stderr, "Error: Image '%s:%s' not found in registry\n", repo, tag);
        fprintf(stderr, "\nAvailable images:\n");
        const char *last_name = "";
        for (int i = 0; official_images[i].name != NULL; i++) {
            /* Skip duplicates for cleaner output */
            char full_name[128];
            snprintf(full_name, sizeof(full_name), "%s:%s", 
                     official_images[i].name, official_images[i].tag);
            if (strcmp(full_name, last_name) != 0) {
                fprintf(stderr, "  %-25s %s\n", full_name, official_images[i].description);
                last_name = official_images[i].name;
            }
        }
        return -1;
    }
    
    printf("Found: %s (~%zu MB)\n", official->description, official->size_mb);
    
    ensure_dirs();
    
    /* Download to cache */
    char cache_file[512];
    snprintf(cache_file, sizeof(cache_file), "%s/%s-%s.txz", 
             LOCHS_CACHE_DIR, repo, tag);
    
    if (download_file(official->url, cache_file) != 0) {
        return -1;
    }
    
    /* Create image directory */
    char image_id[16];
    generate_image_id(repo, tag, image_id);
    
    char image_path[512];
    snprintf(image_path, sizeof(image_path), "%s/%s", LOCHS_IMAGES_DIR, image_id);
    
    /* Extract */
    if (extract_tarball(cache_file, image_path) != 0) {
        fprintf(stderr, "Error: Failed to extract image\n");
        return -1;
    }

    /* Strip bloat from full base images */
    if (strstr(tag, "minimal") == NULL && strstr(tag, "rescue") == NULL) {
        strip_image(image_path);
    }

    /* Get actual size */
    size_t actual_size = get_dir_size(image_path);
    
    /* Register image */
    if (local_image_count >= 128) {
        fprintf(stderr, "Error: Too many local images\n");
        return -1;
    }
    
    lochs_image_t *img = &local_images[local_image_count++];
    memset(img, 0, sizeof(*img));
    safe_strcpy(img->repository, repo, sizeof(img->repository));
    safe_strcpy(img->tag, tag, sizeof(img->tag));
    safe_strcpy(img->id, image_id, sizeof(img->id));
    safe_strcpy(img->path, image_path, sizeof(img->path));
    img->size = actual_size;
    img->created = time(NULL);
    img->pulled = time(NULL);
    
    lochs_images_save();
    
    /* Cleanup cache file */
    unlink(cache_file);
    
    printf("\nSuccessfully pulled %s:%s\n", repo, tag);
    printf("  ID:   %s\n", image_id);
    printf("  Path: %s\n", image_path);
    printf("  Size: %zu MB\n", actual_size / (1024*1024));
    
    return 0;
}

/*
 * List local images
 */
int lochs_image_list_local(void) {
    lochs_images_load();
    
    printf("%-20s %-12s %-14s %-10s %s\n",
           "REPOSITORY", "TAG", "IMAGE ID", "SIZE", "CREATED");
    
    for (int i = 0; i < local_image_count; i++) {
        lochs_image_t *img = &local_images[i];
        
        time_t now = time(NULL);
        int days = (int)((now - img->pulled) / 86400);
        char created_str[32];
        if (days == 0) {
            strcpy(created_str, "today");
        } else if (days == 1) {
            strcpy(created_str, "yesterday");
        } else if (days < 30) {
            snprintf(created_str, sizeof(created_str), "%d days ago", days);
        } else {
            snprintf(created_str, sizeof(created_str), "%d months ago", days / 30);
        }
        
        printf("%-20s %-12s %-14s %-10zu %s\n",
               img->repository,
               img->tag,
               img->id,
               img->size / (1024*1024),
               created_str);
    }
    
    /* Also check for freebsd-root directory as a local image */
    struct stat st;
    if (stat("./freebsd-root", &st) == 0 && S_ISDIR(st.st_mode)) {
        int found = 0;
        for (int i = 0; i < local_image_count; i++) {
            if (strstr(local_images[i].path, "freebsd-root")) {
                found = 1;
                break;
            }
        }
        if (!found) {
            size_t size = get_dir_size("./freebsd-root");
            printf("%-20s %-12s %-14s %-10zu %s\n",
                   "freebsd", "local", "(local)", size / (1024*1024), "local");
        }
    }
    
    if (local_image_count == 0) {
        printf("\nNo images found. Run 'lochs pull freebsd:15' to download an image.\n");
    }
    
    return 0;
}

/*
 * Remove an image
 */
int lochs_image_remove(const char *image_name) {
    char repo[64], tag[32];
    parse_image_name(image_name, repo, sizeof(repo), tag, sizeof(tag));
    
    lochs_images_load();
    
    lochs_image_t *img = find_local_image(repo, tag);
    if (!img) {
        fprintf(stderr, "Error: Image '%s:%s' not found locally\n", repo, tag);
        return -1;
    }
    
    printf("Removing %s:%s...\n", repo, tag);
    
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", img->path);
    int ret = system(cmd);
    
    if (ret != 0) {
        fprintf(stderr, "Warning: Failed to remove image directory\n");
    }
    
    int idx = (int)(img - local_images);
    memmove(&local_images[idx], &local_images[idx + 1],
            (size_t)(local_image_count - idx - 1) * sizeof(lochs_image_t));
    local_image_count--;
    
    lochs_images_save();
    
    printf("Removed image %s:%s\n", repo, tag);
    return 0;
}

/*
 * Get path to image root filesystem
 */
char *lochs_image_get_path(const char *image_name) {
    char repo[64], tag[32];
    parse_image_name(image_name, repo, sizeof(repo), tag, sizeof(tag));
    
    lochs_images_load();
    
    lochs_image_t *img = find_local_image(repo, tag);
    if (img) {
        return strdup(img->path);
    }
    
    /* Check for freebsd-root as fallback */
    if (strcmp(repo, "freebsd") == 0) {
        struct stat st;
        if (stat("./freebsd-root", &st) == 0 && S_ISDIR(st.st_mode)) {
            return strdup("./freebsd-root");
        }
    }
    
    return NULL;
}

/*
 * Search registry for images
 */
int lochs_image_search(const char *query) {
    printf("Searching for '%s'...\n\n", query ? query : "*");
    printf("%-25s %-8s %s\n", "IMAGE", "SIZE", "DESCRIPTION");
    printf("%-25s %-8s %s\n", "-----", "----", "-----------");
    
    int found = 0;
    char last_full[128] = "";
    
    for (int i = 0; official_images[i].name != NULL; i++) {
        /* Check if matches query */
        if (query != NULL && 
            strstr(official_images[i].name, query) == NULL &&
            strstr(official_images[i].description, query) == NULL &&
            strstr(official_images[i].tag, query) == NULL) {
            continue;
        }
        
        /* Skip duplicates */
        char full_name[128];
        snprintf(full_name, sizeof(full_name), "%s:%s", 
                 official_images[i].name, official_images[i].tag);
        if (strcmp(full_name, last_full) == 0) {
            continue;
        }
        safe_strcpy(last_full, full_name, sizeof(last_full));
        
        printf("%-25s %-8zu %s\n",
               full_name,
               official_images[i].size_mb,
               official_images[i].description);
        found++;
    }
    
    if (found == 0) {
        printf("No images found matching '%s'\n", query);
    }
    
    return 0;
}

/*
 * Register a locally built image
 */
int lochs_image_register(const char *name, const char *tag, const char *image_id) {
    lochs_images_load();
    
    /* Check if already exists */
    lochs_image_t *existing = find_local_image(name, tag);
    if (existing) {
        /* Update existing entry */
        safe_strcpy(existing->id, image_id, sizeof(existing->id));
        snprintf(existing->path, sizeof(existing->path), 
                 "%s/%s", LOCHS_IMAGES_DIR, image_id);
        existing->size = get_dir_size(existing->path);
        existing->created = time(NULL);
        existing->pulled = time(NULL);
        lochs_images_save();
        return 0;
    }
    
    /* Add new entry */
    if (local_image_count >= 128) {
        fprintf(stderr, "Error: Too many local images\n");
        return -1;
    }
    
    lochs_image_t *img = &local_images[local_image_count++];
    memset(img, 0, sizeof(*img));
    safe_strcpy(img->repository, name, sizeof(img->repository));
    safe_strcpy(img->tag, tag, sizeof(img->tag));
    safe_strcpy(img->id, image_id, sizeof(img->id));
    snprintf(img->path, sizeof(img->path), "%s/%s", LOCHS_IMAGES_DIR, image_id);
    img->size = get_dir_size(img->path);
    img->created = time(NULL);
    img->pulled = time(NULL);
    
    lochs_images_save();
    return 0;
}
