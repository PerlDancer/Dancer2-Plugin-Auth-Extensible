use strict;
use warnings;

use Test::More;
use Test::WWW::Mechanize::PSGI;

use lib 't/lib';

use Dancer2;
use InsidePluginApp;

set plugins => {
    "Auth::Extensible" => {
        realms => {
            config => {
                provider => 'Config',
            }
        }
    }
};

my $mech = Test::WWW::Mechanize::PSGI->new(
    app => InsidePluginApp->to_app
);

$mech->get ( '/members' );
ok( $mech->status == 302, 'Correct HTTP status code (302) for /members' )
    || diag "Status from response: ", $mech->status ;

done_testing;
