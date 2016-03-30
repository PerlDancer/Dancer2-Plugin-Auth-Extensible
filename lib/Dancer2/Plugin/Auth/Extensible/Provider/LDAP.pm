package Dancer2::Plugin::Auth::Extensible::Provider::LDAP;

use Net::LDAP;
use Moo;
with "Dancer2::Plugin::Auth::Extensible::Role::Provider";
use namespace::clean;

our $VERSION = '0.600';

=head1 NAME 

Dancer2::Plugin::Auth::Extensible::LDAP - LDAP authentication provider


=head1 DESCRIPTION

This class is a generic LDAP authentication provider.

See L<Dancer2::Plugin::Auth::Extensible> for details on how to use the
authentication framework.

This provider requires the following parameters in it's config file:

=over

=item * server

The LDAP server url. 

=cut

has server => (
    is => 'ro',
    required => 1,
);

=item * basedn

The base dn user for all search queries (e.g. 'dc=ofosos,dc=org').

=cut

has basedn => (
    is => 'ro',
    required => 1,
);

=item * authdn

This must be the distinguished name of a user capable of binding to
and reading the directory (e.g. 'cn=Administrator,cn=users,dc=ofosos,dc=org').

=cut

has authdn => (
    is => 'ro',
    required => 1,
);

=item * password

The password of above named user

=cut

has password => (
    is => 'ro',
    required => 1,
);

=item * usergroup

The group where users are to be found (e.g. 'cn=users,dc=ofosos,dc=org')

=cut

has usergroup => (
    is => 'ro',
    required => 1,
);

=item * roles

This is a comma separated list of LDAP group objects that are to be queried.

=cut

has roles => (
    is => 'ro',
    required => 1,
);

=back

=cut

=head1 Class Methods

=over

=item authenticate_user

Given the sAMAccountName and password entered by the user, return true if they are
authenticated, or false if not.

=cut

sub authenticate_user {
    my ($self, $username, $password) = @_;

    my $ldap = Net::LDAP->new($self->server) or die "$!";

    my $mesg = $ldap->bind(
        "cn=" . $username . "," . $self->usergroup,
        password => $password);

    $ldap->unbind;
    $ldap->disconnect;

    return not $mesg->is_error;
}

=item get_user_details

Given a sAMAccountName return the common name (cn), distinguished name (dn) and
user principal name (userPrincipalName) in a hash ref.

=cut

sub get_user_details {
    my ($self, $username) = @_;

    my $ldap = Net::LDAP->new($self->server) or die "$@";

    my $mesg = $ldap->bind(
        $self->authdn,
        password => $self->password);

    if ($mesg->is_error) {
        $self->plugin->app->warning($mesg->error);
    }

    $mesg = $ldap->search(
        base => $self->basedn,
        filter => "(&(objectClass=user)(sAMAccountName=" . $username . "))",
        );

    if ($mesg->is_error) {
        $self->plugin->app->warning($mesg->error);
    }

    my @extract = qw(cn dn name userPrincipalName sAMAccountName);
    my %props = ();

    if ($mesg->entries > 0) {
        foreach my $ex (@extract) {
            $props{$ex} = $mesg->entry(0)->get_value($ex);
        }
    } else {
        $self->plugin->app->warning("Error finding user details.");
    } 

    $ldap->unbind;
    $ldap->disconnect; 

    return \%props;
}

=item get_user_roles

Given a sAMAccountName, return a list of roles that user has.

=cut

sub get_user_roles {
    my ($self, $username) = @_;

    my $ldap = Net::LDAP->new($self->server) or die "$@";

    my $mesg = $ldap->bind(
        $self->authdn,
        password => $self->password);

    if ($mesg->is_error) {
        $self->plugin->app->warning($mesg->error);
    }

    my @relevantroles = split /,/, $self->roles;
    my @roles = ();

    foreach my $role (@relevantroles) {
        $mesg = $ldap->search(
            base => $self->basedn,
            filter => "(&(objectClass=user)(sAMAccountName=" . $username . ")(memberof=cn=". $role . "," . $self->usergroup . "))",
            );
        if ($mesg->is_error) {
            $self->plugin->app->warning($mesg->error);
        }
        if ($mesg->entries > 0) {
            push @roles, $role;
        }
    }

    $ldap->unbind;
    $ldap->disconnect;

    if (@roles == 0) {
        $self->plugin->app->warning($settings->{roles});
    }

    return \@roles;
}

=back

=cut


1;

