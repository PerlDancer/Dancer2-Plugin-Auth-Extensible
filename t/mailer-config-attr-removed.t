use strict;
use warnings;

use Test::More;
use Dancer2::Plugin::Auth::Extensible::Test;
use lib 't/lib';

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'mailer-config-attr-removed';
}

{
    package TestApp;
    use Test::More;
    use Test::Warnings qw/warning :no_end_test/;
    use Dancer2 qw(!warning);
    like warning {
        require Dancer2::Plugin::Auth::Extensible;
        Dancer2::Plugin::Auth::Extensible->import;
    },
      qr/mailer configuration setting for Auth::Extensible is no longer supported/,
      "got warning: mailer configuration setting for Auth::Extensible is no longer supported";
}

done_testing;
