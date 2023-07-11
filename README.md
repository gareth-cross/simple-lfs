## simple-lfs

### Description

A simple S3-backed [git LFS](https://git-lfs.com) server I wrote in C++ for fun and my own edification. This implementation uses [httplib](https://github.com/yhirose/cpp-httplib) to handle HTTP requests. The [AWS SDK](https://aws.amazon.com/sdk-for-cpp/) is employed to upload and download objects from S3.

The server maintains a local copy of all objects. If an object is missing, it is downloaded when next requested by the client. Uploaded objects are written to the local storage, then uploaded asynchronously to the bucket later using the AWS transfer manager API.

Caveats:
- httplib uses blocking IO (with multiple threads to handle parallel requests). This implementation may not scale to a large number of users.
- The AWS SDK officially only supports Amazon S3. I have not tested it with other providers (and would not expect it to work by default).
- Since I run this on a local network, it presently lacks HTTPS (and authentication) support. You probably should not use it (certainly not outside of your LAN).
- No support for the git-lfs [locking API](https://github.com/git-lfs/git-lfs/blob/main/docs/api/locking.md).


### Building

Obtaining dependencies:

git submodules are used for most dependencies.
```
git clone git@github.com:gareth-cross/simple-lfs.git
cd simple-lfs
git submodule update --init --recursive
```

The exception is `OpenSSL`, which must be available for `find_package` to find. On linux, `libuuid-dev` and `pkg-config` are also required.

Building:
```
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -Wno-deprecated
cmake --build . --config RelWithDebInfo
```

### Running

The server requires a configuration TOML file. An example configuration looks like:

```toml
# Bucket name and region:
bucket_name = "your-bucket-name"
bucket_region = "us-west-1"

# Path where the server will locally cache objects.
storage_location = "/path/to/server/storage"

# Path where uploads will be placed while in progress.
# This will default to /tmp if unspecified.
upload_location = "/path/to/uploads"

# Hostname for the HTTP server (defaults to "localhost").
hostname = "localhost"

# Port for the HTTP server (defaults to 6000).
port = 6000

# Credentials. If unspecified, the AWS SDK will look in default locations.
[credentials]
access_key_id = "<YOUR AWS ACCESS ID>"
secret_access_key = "<YOUR AWS SECRET KEY>"
```

The server can be launched with:
```
simplelfs --config <PATH TO TOML FILE>
```

### TODO:
Some improvements I would like to make:
- Automatically trim the local cache.
- Support HTTPS.
