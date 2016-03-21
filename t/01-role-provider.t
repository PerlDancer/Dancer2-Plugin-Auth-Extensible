use strict;
use warnings;

use Test::More tests => 12;
use Test::Exception;
use Dancer2::Core::DSL;
use Dancer2::Plugin::Auth::Extensible;

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
}
"test provider class provides all required methods";

my $password;

ok TestProvider::match_password( undef, 'password', 'password' ),
  "good plain password";

ok TestProvider::match_password( undef, 'password',
    '{SSHA}ljxuwXYQH3BDNZjg+VXBrkw6Sh6sta3l' ),
  "good SHA password";

ok !TestProvider::match_password( undef, 'bad', 'password' ),
  "bad plain password";

ok !TestProvider::match_password( undef, 'bad',
    '{SSHA}ljxuwXYQH3BDNZjg+VXBrkw6Sh6sta3l' ),
  "bad SHA password";

lives_ok { $password = TestProvider::encrypt_password() }
"encrypt_password(undef)";

like $password, qr/^{SSHA}.+$/, "password looks good";

lives_ok { $password = TestProvider::encrypt_password( undef, 'password' ) }
"encrypt_password('password')";

like $password, qr/^{SSHA}.+$/, "password looks good";

lives_ok {
    $password = TestProvider::encrypt_password( undef, 'password', 'SHA-1' )
}
"encrypt_password('password', 'SHA-1')";

like $password, qr/^{SSHA}.+$/, "password looks good";
