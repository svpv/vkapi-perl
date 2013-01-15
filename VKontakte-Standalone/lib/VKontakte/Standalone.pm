package VKontakte::Standalone;

use 5.008000;
use strict;
use warnings;

use URI;
use WWW::Mechanize;
use JSON;
use Carp;

our $VERSION = '0.1';

sub new {
	my ($class,$id) = @_;
	my $self = bless {},$class;
	$self->{api_id} = $id;
	$self->{browser} =  WWW::Mechanize::->new(
		agent => __PACKAGE__.$VERSION,
		autocheck => 1,
	);
	return $self;
}

sub _request {
	my ($self, $params, $base) = @_;
	(my $uri = URI::->new($base))->query_form($params);
	return $self->{browser}->get($uri);
}

sub auth { # dirty hack
	# you have not seen this
	# forget it
	my ($self,$login,$password,$scope) = @_;
	@{$self}{"login","password","scope"} = ($login, $password, $scope); # reuse in case of reauth
	$self->{browser}->get($self->auth_uri($scope));
	$self->{browser}->submit_form(
		with_fields => {
			email => $login,
			pass => $password,
		},
	); # log in
	$self->{browser}->submit unless $self->{browser}->uri =~ m|^https://oauth.vk.com/blank.html|; # allow access if requested to
	return $self->redirected($self->{browser}->uri);
	# you cannot remember what did you just read
}

sub auth_uri {
	my ($self, $scope, $display) = @_;
	(my $uri = URI::->new("https://api.vkontakte.ru/oauth/authorize"))->query_form(
		{
			client_id => $self->{api_id},
			redirect_uri => "blank.html",
			scope => $scope,
			response_type => "token",
			display => $display,
		}
	);
	return $uri->canonical;
}

sub redirected {
	my ($self, $uri) = @_;
	my %params = map { split /=/,$_,2 } split /&/,$1 if $uri =~ m|https://oauth.vk.com/blank.html#(.*)|;
	croak "No access_token returned (wrong login/password?)" unless defined $params{access_token};
	$self->{access_token} = $params{access_token};
	croak "No token expiration time returned" unless $params{expires_in};
	$self->{auth_time} = time;
	$self->{expires_in} = $params{expires_in};
	return $self;
}


sub api {
	my ($self,$method,$params) = @_;
	croak "Cannot make API calls unless authentificated" unless defined $self->{access_token};
	if (time - $self->{auth_time} > $self->{expires_in}) {
		if ($self->{login} && $self->{password} && $self->{scope}) { # you didn't see this
			$self->auth($self->{"login","password","scope"}); # and this
		} else {
			croak "access_token expired";
		}
	}
	$params->{access_token} = $self->{access_token};
	REQUEST: {
		my $response = decode_json $self->_request($params,"https://api.vk.com/method/$method")->decoded_content;
		if ($response->{response}) {
			return $response->{response};
		} elsif ($response->{error}) {
			if (6 == $response->{error}{error_code}) { # Too many requests per second. 
				sleep 1;
				redo REQUEST;
			} elsif (14 == $response->{error}{error_code}) { # Captcha is needed
				if ($self->{captcha_handler}) {
					$params->{captcha_key} = $self->{captcha_handler}->($response->{error}{captcha_img});
					$params->{captcha_sid} = $response->{error}{captcha_sid};
					redo REQUEST;
				} else {
					croak "Captcha is needed and no captcha handler specified";
				}
			} else {
				croak "API call returned error ".$response->{error}{error_msg};
			}
		} else {
			croak "API call didn't return response or error";
		}
	}
}

sub captcha_handler {
	my ($self, $handler) = @_;
	croak "\$handler is not a subroutine reference" unless ref $handler eq "CODE";
	$self->{captcha_handler} = $handler;
	return $self;
}

1;
__END__

=head1 NAME

VKontakte::API::Standalone - Perl extension for creating standalone Vkontakte API applications

=head1 SYNOPSIS

  use VKontakte::API::Standalone;
  my $vk = new VKontakte::API::Standalone "12345678";
  my $auth_uri = $vk->auth_uri("wall,messages");

  # make the user able to enter login and password at this URI
  
  $vk->redirected($where);
  $vk->api("activity.set",{text => "playing with VK API"});


=head1 DESCRIPTION

This module is just a wrapper for some JSON parsing and WWW::Mechanize magic, not much else.

=head1 CONSTRUCTOR METHODS

=over 4

=item $vk = VKontakte::API::Standalone::->new($api_id);

This creates the main object, sets the API ID variable (which can be got from the application
management page) and creates the WWW::Mechanize object.

=back 

=head1 ATTRIBUTES

=begin comment

=item $vk->auth($login,$password,$scope)

This method should be called first. It uses OAuth2 to authentificate the user at the vk.com server
and accepts the specified scope (seen at L<https://vk.com/developers.php?oid=-17680044&p=Application_Access_Rights>).
After obtaining the access token is saved for future use.

=end comment

=over

=item $vk->auth_uri($scope)

This method should be called first. It returns the URI of the login page to show to the user
(developer should call a browser somehow, see L<https://vk.com/developers.php?oid=-17680044&p=Authorizing_Client_Applications>
for more info).

=item $vk->redirected($uri)

This method should be called after a successful authorisation with the URI user was redirected
to. Then the expiration time and the access token are retreived from this URI and stored in
the $vk object.

=item $vk->api($method,{parameter => "value", parameter => "value" ...})

This method calls the API methods on the server, as described on L<https://vk.com/developers.php?oid=-17680044&p=Making_Requests_to_API>.
Resulting JSON is parsed and returned as a hash reference.

=item $vk->captcha_handler($sub)

Sets the sub to call when CAPTCHA needs to be entered.

=back 

=head1 BUGS

Probably many. This is beta version.

=head1 SEE ALSO

L<https://vk.com/developers.php> for the list of methods and how to use them.

=head1 AUTHOR

Krylov Ivan, E<lt>krylov.r00t@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Krylov Ivan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
