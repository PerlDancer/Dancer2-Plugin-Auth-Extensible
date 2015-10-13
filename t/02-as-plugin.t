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

$mech->get_ok ( '/members');

done_testing;
