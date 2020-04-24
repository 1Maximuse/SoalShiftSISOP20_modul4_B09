#define FUSE_USE_VERSION 28

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

char dirPath[100] = "/home/noel/Documents";
char logPath[100] = "/home/noel/fs.log";

char cipherkey[100] = "9(ku@AW1[Lmvgax6q`5Y2Ry?+sF!^HKQiBXCUSe&0M.b%rI'7d)o4~VfZ*{#:}ETt$3J-zpc]lnh8,GwP_ND|jO";
int ciphershift = 10;

char* cipher(char* name, int file) {
    int width = strlen(cipherkey);
    char* ext = strrchr(name, '.');
    int x = 0;
    if (ext != NULL && file) x = strlen(ext);
    for (int i = 0; i < strlen(name)-x; i++) {
        for (int j = 0; j < width; j++) {
            if (name[i] == cipherkey[j]) {
                name[i] = cipherkey[(j + ciphershift) % width];
                break;
            }
        }
    }
    return name;
}

char* decipher(char* name, int file) {
    int width = strlen(cipherkey);
    char* ext = strrchr(name, '.');
    int x = 0;
    if (ext != NULL && file) x = strlen(ext);
    for (int i = 0; i < strlen(name)-x; i++) {
        for (int j = 0; j < width; j++) {
            if (name[i] == cipherkey[j]) {
                name[i] = cipherkey[(j + width - ciphershift) % width];
                break;
            }
        }
    }
    return name;
}

char* processPath(char* path) {
    int enc = 0, a = 1, b = strchr(path+a, '/') - path - 1;
    while (b < strlen(path)) {
        char current[1000];
        strncpy(current, path+a, b-a+1);
        current[b-a+1] = '\0';
        if (enc) {
            cipher(current, 0);
            strncpy(path+a, current, b-a+1);
        }
        if (enc == 0 && strstr(path+a, "encv1_") == path+a) enc = 1;
        a = b+2;
        b = strchr(path+a, '/') - path - 1;
    }
    b = strlen(path) - 1;
    char current[1000];
    strncpy(current, path+a, b-a+1);
    current[b-a+1] = '\0';
    if (enc) {
        cipher(current, 1);
        strncpy(path+a, current, b-a+1);
    }
    return path;
}

char* getFilename(char* path) {
    if (!strcmp(path, "/")) return NULL;
    return strrchr(path, '/')+1;
}

void splitfile(char* path) {
    char prefix[strlen(path) + 5];
    sprintf(prefix, "%s.", path);
    pid_t child = fork();
    if (child == 0) execl("/usr/bin/split", "split", "-b", "1024", "-d", "-a", "3", path, prefix, NULL);
    int status;
    while (wait(&status) > 0);
    unlink(path);
}

void unsplitfile(char* path) {
    char* last4 = path + strlen(path) - 4;
    if (strcmp(last4, ".000")) return;
    last4[0] = '\0';
    FILE* out = fopen(path, "wb");
    char buffer[1500];
    int index = 0;
    while (1) {
        char blockname[strlen(path) + 10];
        sprintf(blockname, "%s.%03d", path, index);
        FILE* f = fopen(blockname, "rb");
        if (!f) break;
        fseek(f, 0L, SEEK_END);
        int size = ftell(f);
        rewind(f);
        fread(buffer, sizeof(char), size, f);
        fwrite(buffer, sizeof(char), size, out);
        fclose(f);
        unlink(blockname);
        index++;
    }
    fclose(out);
}

void info(char* msg) {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    FILE* logFile = fopen(logPath, "a");
    fprintf(logFile, "INFO::%02d%02d%02d-%02d:%02d:%02d::%s\n", (tm.tm_year + 1900) % 100, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, msg);
    fclose(logFile);
}

void warning(char* msg) {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    FILE* logFile = fopen(logPath, "a");
    fprintf(logFile, "WARNING::%02d%02d%02d-%02d:%02d:%02d::%s\n", (tm.tm_year + 1900) % 100, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, msg);
    fclose(logFile);
}

char* joinPath(char* dest, char* a, const char* b) {
    strcpy(dest, a);
    if (!strcmp(b, "/")) {
        return dest;
    }
    if (b[0] != '/') {
        dest[strlen(dest)+1] = '\0';
        dest[strlen(dest)] = '/';
    }
    strcat(dest, b);
    return dest;
}

int encryptedPath(char* path) {
    char* tok = strtok(path, "/");
    char* next = strtok(NULL, "/");
    int out = 0;
    while (next) {
        if (strlen(tok) >= 6 && tok[0] == 'e' && tok[1] == 'n' && tok[2] == 'c' && tok[3] == 'v' && tok[5] == '_') {
            if (tok[4] == '1') {
                out |= 1;
            } else if (tok[4] == '2') {
                out |= 2;
            }
        }
        tok = next;
        next = strtok(NULL, "/");
    }
    return out;
}

int encryptedDir(char* path) {
    char* tok = strtok(path, "/");
    int out = 0;
    while (tok) {
        if (strlen(tok) >= 6 && tok[0] == 'e' && tok[1] == 'n' && tok[2] == 'c' && tok[3] == 'v' && tok[5] == '_') {
            if (tok[4] == '1') {
                out |= 1;
            } else if (tok[4] == '2') {
                out |= 2;
            }
        }
        tok = strtok(NULL, "/");
    }
    return out;
}

void rec_encv1(char* path, int mode) {
    struct dirent* ent;
    DIR* dir;
    if ((dir = opendir(path)) == NULL) return;
    while ((ent = readdir(dir)) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
        char file[strlen(path) + strlen(ent->d_name) + 10];
        joinPath(file, path, ent->d_name);
        char newFile[strlen(file) + 10];
        char newFilename[strlen(ent->d_name) + 10];
        strcpy(newFilename, ent->d_name);
        if (mode == 1) joinPath(newFile, path, cipher(newFilename, 1));
        else if (mode == -1) joinPath(newFile, path, decipher(newFilename, 1));
        if (ent->d_type == DT_DIR) {
            rename(file, newFile);
            rec_encv1(newFile, mode);
        } else if (ent->d_type == DT_REG) {
            rename(file, newFile);
        }
    }
}

void encv1(char* path, int mode) {
    struct stat pathstat;
    stat(path, &pathstat);
    if (!S_ISDIR(pathstat.st_mode)) return;
    rec_encv1(path, mode);
}

void rec_encv2(char* path, int mode) {
    struct dirent* ent;
    DIR* dir;
    if ((dir = opendir(path)) == NULL) return;
    while ((ent = readdir(dir)) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
        char file[strlen(path) + strlen(ent->d_name) + 10];
        joinPath(file, path, ent->d_name);
        if (ent->d_type == DT_DIR) {
            rec_encv2(file, mode);
        } else if (ent->d_type == DT_REG) {
            if (mode == 1) splitfile(file);
            else if (mode == -1) unsplitfile(file);
        }
    }
}

void encv2(char* path, int mode) {
    struct stat pathstat;
    stat(path, &pathstat);
    if (!S_ISDIR(pathstat.st_mode)) return;
    rec_encv2(path, mode);
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = lstat(processPath(fPath), stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = access(processPath(fPath), mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = readlink(processPath(fPath), buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	dp = opendir(processPath(fPath));
	if (dp == NULL)
		return -errno;

    int mode = encryptedDir(fPath);

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        char name[strlen(de->d_name) + 10];
        strcpy(name, de->d_name);
        if (mode == 1) {
            if (de->d_type == DT_REG) decipher(name, 1);
            else if (de->d_type == DT_DIR && strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) decipher(name, 0);
            if (filler(buf, name, &st, 0)) break;
        } else {
            if (filler(buf, name, &st, 0)) break;
        }
    }

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
    processPath(fPath);
	if (S_ISREG(mode)) {
		res = open(fPath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fPath, mode);
	else
		res = mknod(fPath, mode, rdev);
	if (res == -1)
		return -errno;

    char msg[1500];
    sprintf(msg, "MKNOD::%s", fPath);
    info(msg);
	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = mkdir(processPath(fPath), mode);
	if (res == -1)
		return -errno;

    char name[500];
    if (!getFilename(fPath)) return 0;
    strcpy(name, getFilename(fPath));
    if (strlen(name) >= 6) {
        name[6] = '\0';
        if (!strcmp(name, "encv1_")) {
            encv1(fPath, 1);
        } else if (!strcmp(name, "encv2_")) {
            encv2(fPath, 1);
        }
    }
    char msg[1500];
    sprintf(msg, "MKDIR::%s", fPath);
    info(msg);
	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = unlink(processPath(fPath));
	if (res == -1)
		return -errno;

    char msg[1500];
    sprintf(msg, "UNLINK::%s", fPath);
    warning(msg);
	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = rmdir(processPath(fPath));
	if (res == -1)
		return -errno;

    char msg[1500];
    sprintf(msg, "RMDIR::%s", fPath);
    warning(msg);
	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

    char fromPath[1000], toPath[1000];
    joinPath(fromPath, dirPath, from);
    joinPath(toPath, dirPath, to);
	res = rename(processPath(fromPath), processPath(toPath));
	if (res == -1)
		return -errno;

    char name[500];
    int new = 0;
    if (!getFilename(toPath)) return 0;
    strcpy(name, getFilename(toPath));
    if (strlen(name) >= 6) {
        name[6] = '\0';
        if (!strcmp(name, "encv1_")) {
            new = 1;
        } else if (!strcmp(name, "encv2_")) {
            new = 2;
        }
    }
    int old = 0;
    if (!getFilename(fromPath)) return 0;
    strcpy(name, getFilename(fromPath));
    if (strlen(name) >= 6) {
        name[6] = '\0';
        if (!strcmp(name, "encv1_")) {
            old = 1;
        } else if (!strcmp(name, "encv2_")) {
            old = 2;
        }
    }
    if (old == 0) {
        if (new == 1) encv1(toPath, 1);
        else if (new == 2) encv2(toPath, 1);
    } else if (old == 1) {
        if (new != 1) encv1(toPath, -1);
        if (new == 2) encv2(toPath, 1);
    } else if (old == 2) {
        if (new != 2) encv2(toPath, -1);
        if (new == 1) encv1(toPath, 1);
    }
    char msg[2500];
    sprintf(msg, "RENAME::%s::%s", fromPath, toPath);
    info(msg);
	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = chmod(processPath(fPath), mode);
	if (res == -1)
		return -errno;

    char msg[1500];
    sprintf(msg, "CHMOD::%s", fPath);
    info(msg);
	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = lchown(processPath(fPath), uid, gid);
	if (res == -1)
		return -errno;

    char msg[1500];
    sprintf(msg, "CHOWN::%s", fPath);
    info(msg);
	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = truncate(processPath(fPath), size);
	if (res == -1)
		return -errno;

    char msg[1500];
    sprintf(msg, "TRUNCATE::%s", fPath);
    info(msg);
	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = utimes(processPath(fPath), tv);
	if (res == -1)
		return -errno;

    char msg[1500];
    sprintf(msg, "UTIMES::%s", fPath);
    info(msg);
	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = open(processPath(fPath), fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res = 0;

	(void) fi;
    char fPath[1000];
    joinPath(fPath, dirPath, path);
	fd = open(processPath(fPath), O_RDONLY);
	if (fd == -1)
		return -errno;

    res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
    char fPath[1000];
    joinPath(fPath, dirPath, path);
	fd = open(processPath(fPath), O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
    char msg[1500];
    sprintf(msg, "WRITE::%s", fPath);
    info(msg);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

    char fPath[1000];
    joinPath(fPath, dirPath, path);
	res = statvfs(processPath(fPath), stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;

    int res;
    char fPath[1000];
    joinPath(fPath, dirPath, path);
    res = creat(processPath(fPath), mode);
    if(res == -1)
	return -errno;

    close(res);

    char msg[1500];
    sprintf(msg, "CREAT::%s", fPath);
    info(msg);
    return 0;
}

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create     = xmp_create
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &xmp_oper, NULL);
}