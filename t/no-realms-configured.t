use strict;
use warnings;

use Test::More;
use Dancer2::Plugin::Auth::Extensible::Test;
use lib 't/lib';

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'no-realms-configured';
}

{
    package TestApp;
    use Test::More;
    use Test::Warnings qw/warning/;
    use Dancer2 qw(!warning);
    like warning {
        require Dancer2::Plugin::Auth::Extensible;
        Dancer2::Plugin::Auth::Extensible->import;
    },
      qr/No Auth::Extensible realms configured with which to authenticate user/,
      "got warning: No Auth::Extensible realms configured with which to authenticate user";
}

done_testing;
