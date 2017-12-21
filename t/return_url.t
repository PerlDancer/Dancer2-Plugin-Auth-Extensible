use strict;
use warnings;

use Test::More tests => 5;
use Plack::App::URLMap;
use Plack::Test;
use HTTP::Request::Common;
use Data::Dumper;
use URI::URL;
use HTTP::Cookies;

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'return_url';
}

{ 
    package TestApp;
    use Dancer2;
    use Dancer2::Plugin::Auth::Extensible;

    get '/restricted' => require_login sub {
        return "Welcome!";
    };
}

my $app = Plack::App::URLMap->new;
$app->mount("/mypath" => TestApp->to_app);
my $test = Plack::Test->create($app);

my $jar  = HTTP::Cookies->new();
my $res = $test->request(GET '/mypath/restricted');
$jar->extract_cookies($res);
ok($res->code == 302, "Checking response code redirect (302)");
#ok(($res->header('Location') eq 'http://localhost/mypath/login?return_url=%2Frestricted'), "Checking Location in 302 Header");

my $uri = URI::URL->new($res->header('Location'));
my $return_url = $uri->query;
$return_url =~ s/return_url=//;
my $url  = $res->header('Location');

{
    my $req = POST $url, [ username => 'dave', password => 'beer', return_url => $return_url ];
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    $jar->extract_cookies($res);
    
    my $n_req = GET $res->header('Location');
    $jar->add_cookie_header($n_req);
    ok($n_req->url !~ m#/mypath/mypath/#, "Checking duplicate mount path");
    $res = $test->request($n_req);
    ok($res->code != 404, "Checking response code not 404");
    $jar->extract_cookies($res);

    ok $res->is_success, "POST /login with good password response is OK";
    is $res->content, "Welcome!", "... and we see our custom response";
}
