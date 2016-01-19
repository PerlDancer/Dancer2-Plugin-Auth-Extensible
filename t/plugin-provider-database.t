use strict;
use warnings;

use Test::More;
use Module::Load::Conditional 'check_install';
use Dancer2::Plugin::Auth::Extensible::Test;

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'provider-database';
    foreach my $module (qw/DBD::SQLite Dancer2::Plugin::Database/) {
        my $check = check_install( module => $module );
        if ( !$check ) {
            my $msg = "$module required to run these tests";
            die $msg if $ENV{RELEASE_TESTING};
            plan skip_all => $msg;
        }
    }
}

{

    package TestApp;
    use Path::Tiny;
    use Dancer2;
    use Dancer2::Plugin::Database;
    use Dancer2::Plugin::Auth::Extensible;
    use Dancer2::Plugin::Auth::Extensible::Test::App;

    my $dbh1 = database('database1');
    my $dbh2 = database('database2');
    my $ddl  = path('t/database/testapp.ddl');

    $dbh1->do($_)
      for split( /;/,
        join( ';', $ddl->slurp, path('t/database/config1.sql')->slurp ) );

    $dbh2->do($_)
      for split( /;/,
        join( ';', $ddl->slurp, path('t/database/config2.sql')->slurp ) );
}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

Dancer2::Plugin::Auth::Extensible::Test::testme( $app, 'base' );

done_testing;
