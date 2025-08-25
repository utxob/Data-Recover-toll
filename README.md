
**A non-destructive DATA RECOVERY TOLL utility for Kali Linux & Windows**  
Recover deleted files, formatted drives, or perform full drive carving using file signatures.

---

## **Features**

- Recover deleted files using filesystem metadata (NTFS, FAT, exFAT)
- Full drive recovery (file carving from formatted or corrupted drives)
- Supports image formats: E01/EWF
- Auto logging of recovered files
- Supports multiple file types: images, videos, audio, documents, archives, executables
- Interactive CLI menu for beginners
- Filters for file extension, filename substring, and maximum size

---

## **Supported File Types**

| Type        | Extensions / Notes |
|------------ |------------------|
| Images      | jpg, png, gif, bmp, tiff |
| Video       | mp4, avi, mkv, mov, flv |
| Audio       | mp3, wav, aac, flac |
| Documents   | doc, docx, xls, xlsx, ppt, pptx, pdf |
| Archives    | zip, rar, rar5, 7z |
| Executables | exe |
| Web         | html, css, js |

**Note:** Files overwritten by new data, SSDs with TRIM enabled, or encrypted/corrupted files may not recover.

---

## **Installation**

### **Linux (Debian/Ubuntu/Kali)**
1. Open terminal and update:
```bash
sudo apt update
sudo apt install python3 python3-pip python3-dev libtsk-dev libewf-dev build-essential -y

```

# Installation Instructions

## Linux / macOS

### 2. Install Python dependencies:
```bash
pip3 install pytsk3 pyewf tqdm
```

## Windows

### 1. Install Python 3.x from [python.org](https://python.org)

### 2. Open Command Prompt as Administrator

### 3. Install dependencies:
```cmd
pip install pytsk3 pyewf tqdm
```


# Running the Tool

## Interactive CLI Mode

```bash
python3 file_recovery_tool.py --interactive
```

============================================================
ENHANCED FILE RECOVERY TOOL - MAIN MENU
============================================================
1. Recover Deleted Files (using filesystem metadata)
2. Full Drive Carving (file signature scanning)
3. Show Help
4. Exit
5. chose option:


# Recover Deleted Files (Option 1)

## Steps:

1. **Type `1` and press Enter**

2. **Enter source path:**
   - Example Linux: `/dev/sdb1`
   - Example Windows: `D:\` or `D:`

3. **Recursive scanning? (y/n)** – Default `y`, press Enter

4. **File extensions to recover** (comma separated) – Leave empty for all

5. **Filename contains** (substring filter) – Leave empty for all

6. **Maximum file size** (in bytes) – Leave empty for no limit

7. **Recovery starts**, progress shown in terminal

8. **Recovered files saved in folder:**

**recovery_output_YYYYMMDD_HHMMSS/deleted_files/**


# Full Drive Recovery (Option 2)

## Steps:

1. **Type `2` and press Enter**

2. **Enter source path:**
   - Example Linux: `/dev/sdb`
   - Example Windows: `D:\`

3. **Chunk size in MB** (default 64) – Press Enter to use default

4. **File extensions to recover** – Leave empty for all

5. **Filename substring filter** – Leave empty for all

6. **Maximum file size** – Leave empty for no limit

7. **Tool scans drive** with file signature carving

8. **Progress bar** shows scanning progress

9. **Recovered files saved in folder:**


# Tips & Notes

## Important Considerations
- **Use read-only mode** - Do not write to the source drive during recovery
- **SSD limitations** - Files on SSDs with TRIM enabled or overwritten files may not be recoverable
- **Time requirements** - Large drives may take hours for full recovery

## CLI Configuration Tips
- **Recursive scanning**: Default `y` (press Enter to accept)
- **Chunk size**: Default 64 MB (increase for faster scanning on systems with more RAM)
- **Use filters** to limit file types or sizes to speed up recovery process

## Performance Optimization
- Specify file extensions to focus search
- Use filename substring filters when possible  
- Set maximum file size limits to exclude very large files
- Increase chunk size for faster processing on capable hardware


## Recover deleted files from D drive:
```bash
python3 file_recover.py D: -m deleted -e jpg,pdf,docx D: -m deleted -e jpg,pdf,docx
```

Interactive mode:

```bash
python3 file_recover.py --interactive
```

Additional Examples:

Recover PDF files containing "report" from external drive:

```bash
python3 file_recover.py /dev/sdc1 -m deleted -e pdf -n report
```

Full carving with 128MB chunks and PNG files only:

```bash
python3 file_recover.py E: -m full -c 128 -e png
```

Note: Replace drive letters and paths with your specific source device
