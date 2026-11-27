//! Extension → kind. Stage 1 of type detection: no I/O, ~94% coverage.

pub fn from_ext(ext: &str) -> &'static str {
    match ext {
        "pdf" | "doc" | "docx" | "odt" | "rtf" | "pages" | "txt" | "md" | "tex" => "document",
        "ppt" | "pptx" | "key" | "odp" => "slides",
        "xls" | "xlsx" | "xlsm" | "csv" | "tsv" | "numbers" | "ods" => "sheet",
        "jpg" | "jpeg" | "png" | "gif" | "heic" | "heif" | "webp" | "tif" | "tiff" | "bmp"
        | "svg" | "raw" | "cr2" | "nef" | "arw" | "dng" | "psd" | "ai" | "ico" | "icns" => "image",
        "mp4" | "mov" | "m4v" | "mkv" | "avi" | "webm" | "wmv" | "flv" | "mpg" | "mpeg" => "video",
        "mp3" | "m4a" | "aac" | "wav" | "flac" | "ogg" | "opus" | "aiff" | "aif" => "audio",
        "zip" | "gz" | "tgz" | "bz2" | "xz" | "zst" | "7z" | "rar" | "tar" | "jar" | "war"
        | "whl" | "nupkg" | "apk" | "crate" => "archive",
        "dmg" | "iso" | "img" | "sparseimage" | "vmdk" | "qcow2" | "vdi" | "pkg" => "diskimage",
        "rs" | "go" | "py" | "pyi" | "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "java" | "kt"
        | "c" | "h" | "cc" | "cpp" | "hpp" | "cs" | "rb" | "php" | "swift" | "m" | "scala"
        | "sh" | "bash" | "zsh" | "fish" | "ps1" | "tf" | "hcl" | "lua" | "pl" | "r" | "sql"
        | "html" | "htm" | "css" | "scss" | "vue" | "svelte" | "zig" | "ex" | "exs" | "erl"
        | "hs" | "ml" | "clj" | "dart" | "groovy" | "gradle" | "makefile" | "cmake" => "code",
        "json" | "jsonl" | "ndjson" | "yaml" | "yml" | "toml" | "xml" | "ini" | "cfg" | "conf"
        | "parquet" | "avro" | "orc" | "sqlite" | "db" | "sqlite3" | "gpkg" | "geojson"
        | "plist" | "lock" | "env" | "properties" | "proto" | "ipynb" | "log" | "dat" => "data",
        "ttf" | "otf" | "woff" | "woff2" | "eot" => "font",
        "dylib" | "so" | "dll" | "exe" | "a" | "o" | "pyc" | "class" | "wasm" | "bin" | "node" => "binary",
        "epub" | "mobi" | "azw" | "azw3" => "ebook",
        "eml" | "msg" | "mbox" | "emlx" => "mail",
        _ => "other",
    }
}

/// Lowercased extension of a file name ("" if none; dotfiles have none).
pub fn ext_of(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() && name.len() - i <= 11 => name[i + 1..].to_lowercase(),
        _ => String::new(),
    }
}

/// Kind from a MIME type returned by magic-byte sniffing (stage 2).
pub fn from_mime(mime: &str, ext_hint: &str) -> &'static str {
    let k = from_ext(ext_hint);
    if k != "other" {
        return k;
    }
    match mime.split('/').next().unwrap_or("") {
        "image" => "image",
        "video" => "video",
        "audio" => "audio",
        "font" => "font",
        _ => match mime {
            "application/pdf" | "application/rtf" => "document",
            "application/zip" | "application/gzip" | "application/x-tar" | "application/x-xz"
            | "application/x-bzip2" | "application/zstd" | "application/x-7z-compressed"
            | "application/vnd.rar" => "archive",
            "application/x-mach-binary" | "application/x-executable" | "application/x-sharedlib"
            | "application/wasm" => "binary",
            "application/x-apple-diskimage" => "diskimage",
            "application/vnd.sqlite3" => "data",
            _ if mime.contains("presentation") => "slides",
            _ if mime.contains("spreadsheet") || mime.contains("excel") => "sheet",
            _ if mime.contains("word") || mime.contains("opendocument.text") => "document",
            _ => "other",
        },
    }
}
