# SoalShiftSISOP20_modul4_B09
Soal Shift Sistem Operasi 2020 Modul 4 Kelompok B09

## SSFS
> Source code: [ssfs.c](https://github.com/1Maximuse/SoalShiftSISOP20_modul4_B09/blob/master/ssfs.c)

Untuk sub-soal pertama, kita diminta membuat sebuah metode enkripsi yang dapat melakukan *caesar cipher* pada direktori yang ditentukan.

Caesar cipher dilakukan dengan menggunakan kode berikut:

```c
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
```

Agar file dapat ditampilkan secara normal di dalam filesystem, untuk setiap fungsi implementasi FUSE, alamat yang diakses perlu "dikembalikan" ke semula terlebih dahulu. Maka, digunakan fungsi untuk "mengembalikan" suatu alamat atau *path* yang akan diakses:

```c
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
```

Pada setiap perintah `mkdir` dan `rename`, pertama-tama di cek apakah folder yang dibuat atau direname mengandung nama `encv1_` sebagai awalan. Apabila iya, maka dijalankan fungsi rekursif yang akan melakukan cipher kepada keseluruhan subfolder.

Sebaliknya untuk perintah `rename` apabila folder yang sebelumnya ber-*suffix* `encv1_` diubah menjadi folder yang tidak terenkripsi, maka dijalankan fungsi rekursif yang akan mengembalikannya.

---

Untuk sub-soal nomor dua, sebagian besar cara pendeteksian nama folder dan rekursi sama. Bedanya, untuk setiap file dilakukan `split` agar file terpecah-pecah menjadi ukuran 1024 byte masing-masingnya.

```c
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
```

Agar file dapat terbaca dengan normal, pertama fungsi `readdir()` implementasi FUSE perlu diubah agar file-file dengan format nama terpecah (`<nama>.000` &ndash; `<nama>.999`) tidak terbaca. Sebaliknya, fungsi tersebut akan mengembalikan hanya satu file yaitu `<nama>` saja. **(Not implemented)**

Kemudian, pada implementasi fungsi `read()` diubah sehingga setiap pembacaan file dilakukan looping untuk membaca semua file-file pecahannya, dan dioutputkan ke buffer sebagai satu file. **(Not implemented)**

---

Untuk sub-soal ketiga, kita diminta membuat folder sinkronisasi yang akan dideteksi dengan awalan `sync_`.

---

Untuk sub-soal keempat, kita diminta membuat *logfile* di operasi-operasi tertentu. Maka, dibuat sebuah fungsi *helper* untuk fungsi *logging*:

```c
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
```

Fungsi itu dapat dipanggil pada fungsi-fungsi implementasi FUSE untuk keperluan *logging*.
