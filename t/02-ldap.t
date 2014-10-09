use strict;
use warnings;

use Test::More import => ['!pass'];
use Mock::Quick;

my $auth_as = '';

my $noerr = qclass(
    -with_new => 1,
    is_error => 0,
    );
    
my $err = qclass(
    -with_new => 1,
    is_error => 1,
    error => 'bogus mock',
    );
    
my $emptyentries = qclass(
    -with_new => 0,
    is_error => 0,
    entries => 0,
    );
    
my $entries1 = qclass(
    -with_new => 1,
    is_error => 0,
    entries => 1,
    );

my $entry1 = qclass(
    -with_new => 1,
    vals => {cn => "David Precious", dn => 'dprecious', name => 'David Precious', userPrincipalName => 'dprecious@foo.com', sAMAccountName => 'dprecious'},
    get_value => sub { 
        my $self = shift;
        my $arg = shift;
        return $self->vals()->{$arg};
        },
    );
    
my $detail = qclass(
    -with_new => 1,
    is_error => 0,
    entries => 1,
    entry => sub { return $entry1->package->new; },
    );

my $mod = qclass(
    -implement => 'Net::LDAP',
    -with_new => 0,
    new => sub { my $cls = shift; 
    bless {}, $cls; },
    disconnect => sub { },
    unbind => sub { $auth_as = ''; },
    bind => sub { if ($_[1] =~ /^cn=dprecious,/) { return $noerr->package->new; } else { return $err->package->new; } },
    search => sub {
        my $self = shift;
        my %args = @_;
        if (my ($uname) = $args{filter} =~ /^\(&\(objectClass=user\)\(sAMAccountName=([^,]+)\)$/) {
            return $detail->package->new;
        } elsif (my ($name, $role) = $args{filter} =~ /^\(\&\(objectClass=user\)\(sAMAccountName=(.+)\)\(memberof=cn=([^,]+)/) {
            if ($name eq "dprecious") {
                
                diag("ROLE: " . $role);
                if ($role eq "Jever" or $role eq "Budvar") {
                    return $entries1->package->new;
                } else {
                    return $emptyentries->package->new;
                }
            }
            return $emptyentries->package->new;
        } else {
            return $err->package->new;
        }
    },
);

use Plack::Test;
use t::lib::TestSub;

{
    package MyApp;
    use Dancer2;
    use t::ldap::LDAPTestApp;
}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

test_psgi $app, t::lib::TestSub::test_the_app_sub);

done_testing();


