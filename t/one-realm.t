use strict;
use warnings;

use Test::More;
use Plack::Test;
use HTTP::Request::Common;
use lib 't/lib';

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'one-realm';
}

{

    package TestApp;
    use Test::More;
    use Test::Deep;
    use Test::Fatal;
    use Dancer2;
    use Dancer2::Plugin::Auth::Extensible;

    my $plugin = app->with_plugin('Auth::Extensible');
    my $trap   = dancer_app->logger_engine->trapper;
    my $logs;

    is exception {
        $plugin->create_user( username => 'one-realm1', password => 'pwd1' );
    }, undef, "No need to pass realm to create_user since we have only one.";

    post '/create_user' => sub {
        my $params = body_parameters->as_hashref;
        my $user   = create_user %$params;
        return $user ? 1 : 0;
    };
}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

my $test = Plack::Test->create($app);
my $url  = 'http://localhost';

{
    my $res =
      $test->request( POST "$url/create_user", [ username => 'one-realm2' ] );
    ok $res->is_success, "POST /create_user is_success";
    is $res->content, 1, "... and response shows user was created.";
}

done_testing;
