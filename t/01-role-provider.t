use strict;
use warnings;

use Test::More tests => 15;
use Test::Exception;
use Dancer2::Core::DSL;

throws_ok {
    package BadTestProvider;
    use Moo;
    with 'Dancer2::Plugin::Auth::Extensible::Role::Provider';
    use namespace::clean;
}
qr/missing.+authenticate_user/,
  "test provider class does not supply any required methods";


lives_ok {
    package TestProvider;
    use Moo;
    with 'Dancer2::Plugin::Auth::Extensible::Role::Provider';
    use namespace::clean;
    sub authenticate_user { }
    sub get_user_details  { }
    sub get_user_roles    { }
} "test provider class provides all required methods";

my ( $provider, $password );

lives_ok {
    $provider = TestProvider->new(
        realm_settings => { realm_info                 => 'none' },
        realm_dsl      => Dancer2::Core::DSL->new( app => [] )
      )
}
"TestProvider->new";

can_ok 'Dancer2::Plugin::Auth::Extensible::Role::Provider',
  qw(realm_settings realm_dsl);

can_ok 'TestProvider',
  qw(realm_settings realm_dsl authenticate_user get_user_details get_user_roles);

ok $provider->match_password( 'password', 'password' ), "good plain password";
ok $provider->match_password(
    'password', '{SSHA}ljxuwXYQH3BDNZjg+VXBrkw6Sh6sta3l'
  ),
  "good SHA password";

ok !$provider->match_password( 'bad', 'password' ), "bad plain password";
ok !$provider->match_password( 'bad',
    '{SSHA}ljxuwXYQH3BDNZjg+VXBrkw6Sh6sta3l' ), "bad SHA password";

lives_ok { $password = $provider->encrypt_password } "encrypt_password(undef)";
like $password, qr/^{SSHA}.+$/, "password looks good";

lives_ok { $password = $provider->encrypt_password('password') }
"encrypt_password('password')";
like $password, qr/^{SSHA}.+$/, "password looks good";

lives_ok { $password = $provider->encrypt_password( 'password', 'SHA-1' ) }
"encrypt_password('password', 'SHA-1')";
like $password, qr/^{SSHA}.+$/, "password looks good";
