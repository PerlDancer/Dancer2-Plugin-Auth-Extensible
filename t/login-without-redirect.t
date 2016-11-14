use strict;
use warnings;

use Test::More;
use Plack::Test;
use HTTP::Request::Common;
use HTTP::Cookies;

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'login-without-redirect';
}

{

    package TestApp;
    use lib 't/lib';
    use Dancer2;
    use Dancer2::Plugin::Auth::Extensible;

    set logger => 'capture';
    set log    => 'debug';

    get '/loggedin' => require_login sub {
        "You are logged in";
    };

    get '/beer' => require_role BeerDrinker => sub {
        "Have some beer";
    };

}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

my $test = Plack::Test->create($app);
my $trap = TestApp->dancer_app->logger_engine->trapper;
my $url  = 'http://localhost';
my $jar  = HTTP::Cookies->new();

my %ua = ( 'User-Agent' => 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.1 (KHTML like Gecko) Chrome/21.0.1180.83 Safari/537.1' );

{
    my $res = $test->request( GET "$url/loggedin", %ua );
    $jar->extract_cookies($res);
    is $res->code, 401,
      "Trying a protected page with real User-Agent header gets 401 response";
    like $res->header('www-authenticate'), qr/FormBased.+use form to log in/,
      "... and we have a WWW-Authenticate header which says use the form";
    like $res->content, qr/You need to log in to continue/,
      "... and we can see a login form";
    like $res->content, qr/input.+name="__auth_extensible_username/,
      "... and we see __auth_extensible_username field.";

}
{
    my $res = $test->request( GET "$url/loggedin" );
    $jar->extract_cookies($res);
    is $res->code, 401,
      "Trying a protected page with *no* User-Agent header gets 401 response";
    like $res->header('www-authenticate'), qr/Basic realm=/,
      "... and we have a WWW-Authenticate header with Basic realm";
    like $res->content, qr/You need to log in to continue/,
      "... and we can see a login form";
    like $res->content, qr/input.+name="__auth_extensible_username/,
      "... and we see __auth_extensible_username field.";
}
done_testing;
__END__
{
    my $req = POST "$url/login", [ username => 'dave', password => 'bad' ];
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_success, "POST /login with bad password response is OK";
    is $res->content, "Not allowed", "... and we see our custom response.";
}
{
    my $req = GET "$url/loggedin";
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_redirect, "... and we still cannot reach protected page.";
}
{
    my $req = POST "$url/login", [ username => 'dave', password => 'beer' ];
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_success, "POST /login with good password response is OK";
    is $res->content, "Welcome!", "... and we see our custom response";
}
{
    my $req = GET "$url/loggedin";
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_success, "... and we can reach protected page";
    is $res->content,    "You are logged in",
      "... which has the content we expect.";
}
{
    my $req = GET "$url/logout";
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_success, "/logout is successful";
}
{
    my $req = GET "$url/loggedin";
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_redirect, "... and we can no longer reach protected page.";
}

done_testing;
