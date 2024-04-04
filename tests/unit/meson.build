tests = [
    'buffer',
    'parse',
    'scan',
    ]

foreach tst : tests
    exe = executable('test_' + tst, 'test_' + tst + '.c',
        link_with : [
            libsic
        ],
        include_directories : [
            inc_dir
        ],
        dependencies : [
            llvm_dep
        ])
    test(tst, exe)
endforeach
