use strict;
use warnings;

use Test::Fatal;
use Test::More;
use Dancer2::Plugin::Auth::Extensible::Test;
use Plack::Test;
use HTTP::Request::Common;
use aliased 'Dancer2::Plugin::Auth::Extensible::Provider::LDAP';

BEGIN {
    $ENV{DANCER_CONFDIR} = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'provider-ldap';
}

{
    package TestApp;
    use Dancer2;
    use Dancer2::Plugin::Auth::Extensible::Test::App;

    #set logger => 'console';

    get '/ldap' => sub {
        my $plugin = app->with_plugin('Auth::Extensible');
        my $auth_provider = $plugin->auth_provider('ldap1');
        my $ldap = $auth_provider->ldap;
        use DDP;
        p $plugin;
        p $auth_provider;
        p $ldap;
        return 1;
    };
}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

#subtest '... LDAP provider base tests' => sub {

#    my $test = Plack::Test->create($app);
#    my $res = $test->request( GET '/ldap' );
    #ok $res->is_success, 'Successful request';
    #diag explain $res->content;
#};

Dancer2::Plugin::Auth::Extensible::Test::testme($app, 'base');

done_testing;
