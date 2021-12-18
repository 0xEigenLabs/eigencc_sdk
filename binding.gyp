{
    "targets": [
        {
            "target_name": "tee_task",
            "cflags!": ["-fno-exceptions"],
            "cflags_cc!": ["-fno-exceptions"],
            "sources": ["tee_task.c"],
            "include_dirs": [
                "<!@(node -p \"require('node-addon-api').include\")"
            ],
            "libraries": ["<(module_root_dir)/deps/libsdk_c.so"]
        }
    ]
}
