use inc::Module::Install;

name	'STUN-Client';
author q{Thiago Rondon <thiago@aware.com.br>};
license 'perl';
perl_version '5.10.0';
all_from 'lib/STUN/Client.pm';
build_requires 'Test::More';
build_requires 'Test::UseAllModules';

requires 'Moose';
requires 'Moose::Util::TypeConstraints';
requires 'Socket';
requires 'String::Random';

requires 'Test::More';
requires 'Test::Exception';
requires 'Data::Validate::IP';

auto_install;

WriteAll;

