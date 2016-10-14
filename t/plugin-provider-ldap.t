use strict;
use warnings;

use Test::Fatal;
use Test::More;
use Dancer2::Plugin::Auth::Extensible::Test;

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'provider-ldap';
    eval "use Test::Net::LDAP";
    plan skip_all => "Test::Net::LDAP required for these tests" if $@;
}

use Test::Net::LDAP::Mock;
use Test::Net::LDAP::Util qw(ldap_mockify);

Test::Net::LDAP::Mock->mock_target('ldap://127.0.0.1:389');
Test::Net::LDAP::Mock->mock_target(
    'localhost',
    port   => 389,
    schema => 'ldap'
);

{
    package TestApp;
    use Dancer2;
    use Dancer2::Plugin::Auth::Extensible::Test::App;

}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );


ldap_mockify {
    my $ldap = Net::LDAP->new( '127.0.0.1', port => 389 );
    $ldap->mock_root_dse( namingContexts => 'dc=localnet' );

    $ldap->add( 'cn=admin, dc=localnet', attrs => [], );
    $ldap->mock_password( 'cn=admin, dc=localnet', 'Eec8aireiZ0bo7Shooxe' );

    $ldap->add(
        'uid=dave, ou=People, dc=localnet',
        attrs => [
            objectClass =>
              [ 'inetOrgPerson', 'organizationalPerson', 'person', 'top' ],
            cn  => 'David Precious',
            sn  => 'Precious',
            uid => 'dave',
        ]
    );
    $ldap->mock_password( 'uid=dave, ou=People, dc=localnet', 'beer' );
    $ldap->add(
        'cn=BeerDrinker, ou=Groups, dc=localnet',
        attrs => [
            objectClass => [ 'groupOfNames', 'top' ],
            cn          => 'BeerDrinker',
            member      => 'uid=dave, ou=People, dc=localnet',
        ]
    );
    $ldap->add(
        'cn=Motorcyclist, ou=Groups, dc=localnet',
        attrs => [
            objectClass => [ 'groupOfNames', 'top' ],
            cn          => 'Motorcyclist',
            member      => 'uid=dave, ou=People, dc=localnet',
        ]
    );

    $ldap->add(
        'uid=bob, ou=People, dc=localnet',
        attrs => [
            objectClass =>
              [ 'inetOrgPerson', 'organizationalPerson', 'person', 'top' ],
            cn  => 'Bob Smith',
            sn  => 'Smith',
            uid => 'bob',
        ]
    );
    $ldap->mock_password( 'uid=bob, ou=People, dc=localnet', 'cider' );
    $ldap->add(
        'cn=CiderDrinker, ou=Groups, dc=localnet',
        attrs => [
            objectClass => [ 'groupOfNames', 'top' ],
            cn          => 'CiderDrinker',
            member      => 'uid=bob, ou=People, dc=localnet',
        ]
    );

    $ldap->add(
        'cn=burt, ou=People, dc=localnet',
        attrs => [
            objectClass =>
              [ 'inetOrgPerson', 'organizationalPerson', 'person', 'top' ],
            cn           => 'burt',
            sn           => 'Burt',
            displayName  => 'Burt',
            employeeType => 'staff',
        ]
    );
    $ldap->mock_password( 'cn=burt, ou=People, dc=localnet', 'bacharach' );

    $ldap->add(
        'cn=hashedpassword,ou=People,dc=localnet',
        attrs => [
            objectClass =>
              [ 'inetOrgPerson', 'organizationalPerson', 'person', 'top' ],
            cn           => 'hashedpassword',
            sn           => 'hashedpassword',
            displayName  => 'hashedpassword',
            employeeType => 'staff',
        ]
    );
    $ldap->mock_password( 'cn=hashedpassword, ou=People, dc=localnet',
        'password' );

    Dancer2::Plugin::Auth::Extensible::Test::testme( $app, 'base' );
};

done_testing;
