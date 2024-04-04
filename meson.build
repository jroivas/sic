project('sic', 'c', 'cpp')

inc_dir = include_directories('inc')

llvm_dep = dependency('llvm',
    required : true)

subdir('src')
subdir('tools')
subdir('tests')

sic = executable('sic',
    'main.c',
    link_with : [
        libsic
    ],
    include_directories : [
        inc_dir
    ],
    dependencies : [
        llvm_dep
    ])
