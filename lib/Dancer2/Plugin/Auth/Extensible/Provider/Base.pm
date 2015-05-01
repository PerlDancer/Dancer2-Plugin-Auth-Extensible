package Dancer2::Plugin::Auth::Extensible::Provider::Base;

use strict;
use Crypt::SaltedHash;

our $VERSION = '0.306';

=head1 NAME

Dancer2::Plugin::Auth::Extensible::Provider::Base - base class for authentication providers

=head1 DESCRIPTION

Base class for authentication providers.  Provides a constructor which handles
receiving the realm settings and returning an instance of the provider.

Also provides secure password matching which automatically handles crypted
passwords via Crypt::SaltedHash.

Finally, provides the methods which providers must override with their
implementation, which will die if they are not overridden.

=cut

sub new {
    my ($class, $realm_settings, $dsl) = @_;
    my $self = {
        realm_settings => $realm_settings,
        dsl => $dsl,
    };
    return bless $self => $class;
}

=head1 METHODS SUPPLIED BY BASE PROVIDER

=head2 realm_settings

Accessor for realm settings.

=head2 realm_dsl

Accessor for realm DSL object.

=head2 match_password($given, $correct)

Matches C<$given> password with the C<$correct> one.

=head2 encrypt_password($password, $algorithm)

Encrypts password C<$password> with C<$algorithm> which defaults to SHA-1.

=head1 METHODS IMPLEMENTED BY PROVIDER

=head2 authenticate_user

=head2 get_user_details

=head2 set_user_details

=head2 get_user_roles

=head2 set_user_password

=cut

sub realm_settings { shift->{realm_settings} || {} }
sub realm_dsl { shift->{dsl} }

sub match_password {
    my ($self, $given, $correct) = @_;

    # TODO: perhaps we should accept a configuration option to state whether
    # passwords are crypted or not, rather than guessing by looking for the
    # {...} tag at the start.
    # I wanted to let it try straightforward comparison first, then try
    # Crypt::SaltedHash->validate, but that has a weakness: if a list of hashed
    # passwords got leaked, you could use the hashed password *as it is* to log
    # in, rather than cracking it first.  That's obviously Not Fucking Good.
    # TODO: think about this more.  This shit is important.  I'm thinking a
    # config option to indicate whether passwords are crypted - yes, no, auto
    # (where auto would do the current guesswork, and yes/no would just do as
    # told.)
    if ($correct =~ /^{.+}/) {
        # Looks like a crypted password starting with the scheme, so try to
        # validate it with Crypt::SaltedHash:
        return Crypt::SaltedHash->validate($correct, $given);
    } else {
        # Straightforward comparison, then:
        return $given eq $correct;
    }
}


sub encrypt_password {
    my ($self, $password, $algorithm) = @_;
    $algorithm ||= 'SHA-1';
    my $crypt = Crypt::SaltedHash->new(algorithm => $algorithm);
    $crypt->add($password);
    $crypt->generate;
}



# Install basic method placeholders which will blow up if the provider module
# did not implement their own version. 
{
    no strict 'refs';
    for my $method (qw(
        authenticate_user
        get_user_details
        set_user_details
        get_user_roles
        set_user_password
        password_expired
        ))
    {
        *$method = sub {
            die "$method was not implemented by provider " . __PACKAGE__;
        };
    }
}




1;

