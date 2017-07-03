DROP TABLE IF EXISTS package_basic;
CREATE TABLE package_basic
(
    pkg_name VARCHAR(512),
    app_name VARCHAR(512),
    version_code VARCHAR(32),
    version_name VARCHAR(32),
    apk_size INT,
    md5 CHAR(32),
    sha1 CHAR(40),
    cert TEXT,
    android_manifest TEXT,
    strings TEXT,
    activities TEXT,

)