#!/usr/bin/perl

# This script imports CentOS Errata into Katello
# It relies on preformatted information since parsing email
# is the road to madness...
#
# To run this script on CentOS 5.x you need
# perl-XML-Simple, perl-XML-Parser, perl-Text-Unidecode and perl-Frontier-RPC
#
# This script was modified from Steve Meier's script which
# can be found at http://cefs.steve-meier.de/
#


# Test for required modules
&eval_modules;

# Load modules
use strict;
use warnings;
use Data::Dumper;
use Getopt::Long;

use HTTP::Request::Common;
use REST::Client;
use JSON; # imports encode_json, decode_json, to_json and from_json.

import Text::Unidecode;
import XML::Simple;
import XML::Parser;

# Version information
my $version = "20170130";

# Constants
use constant ADMIN_CERT_PEM => "$ENV{HOME}/.pulp/cert.pem";
use constant ADMIN_PRIV_PEM => "$ENV{HOME}/.pulp/priv.pem";

# Variable declation
$| = 1;
my $host;
my ($xml, $erratafile, $rhsaxml, $rhsaovalfile);
my (%name2id, %name2channel, %name2filename);
my $debug = 0;
my $quiet = 0;
my $pulp_args = '';
my $getopt;
my $reference;
my $result;
my ($pkg, $allpkg, @pkgdetails, $package);
my @packages;
my @channels;
my ($title, $type, $synopsis, $severity);
my ($advisory, $advid, $ovalid);
my %existing;
my @repolist;

# Print call and parameters if in debug mode (GetOptions will clear @ARGV)
if (join(' ',@ARGV) =~ /--debug/) { print STDERR "DEBUG: Called as $0 ".join(' ',@ARGV)."\n"; }

# Parse arguments
$getopt = GetOptions( 'errata=s'		=> \$erratafile,
                      'rhsa-oval=s'		=> \$rhsaovalfile,
                      'debug'			=> \$debug,
                      'quiet'			=> \$quiet,
                      'host=s'			=> \$host,
                      'include-repo=s{,}'	=> \@repolist
                     );

# Check for arguments
if ( not(defined($erratafile))) {
  &usage;
  exit 1;
}

if (not(defined($host))) {
  &usage;
  exit 1;
}

# Do we have a proper errata file?
if (not(-f $erratafile)) {
  &error("$erratafile is not an errata file!\n");
  exit 1;
}

# Output $version string in debug mode
&debug("Version is $version\n");

# XML::Parser is 10x as fast loading these XML files as XML::SAX
$ENV{XML_SIMPLE_PREFERRED_PARSER} = 'XML::Parser';

# initialize the REST client
my $client = REST::Client->new(
	host => $host,
	cert => ADMIN_CERT_PEM,
	key => ADMIN_PRIV_PEM,
);

############################
# Read the XML errata file #
############################
&info("Loading errata XML\n");
if (not($xml = XMLin($erratafile))) {
  &error("Could not parse errata file!\n");
  exit 4;
}
&debug("XML loaded successfully\n");

# Check that we can handle the data
if (defined($xml->{meta}->{minver})) {
  if ($xml->{meta}->{minver} > $version) {
    &error("This script is too old to handle this data file. Please update.\n");
    exit 5;
  }
}

##################################
# Load optional Red Hat OVAL XML #
##################################
if (defined($rhsaovalfile)) {
  if (-f $rhsaovalfile) {
    &info("Loading Red Hat OVAL XML\n");
    if (not($rhsaxml = XMLin($rhsaovalfile))) {
      &error("Could not parse Red Hat OVAL file!\n");
      exit 4;
    }

    &debug("Red Hat OVAL XML loaded successfully\n");
  }
}

########################
# Get server inventory #
########################
&info("Getting server inventory\n");

if(!@repolist) {
  &debug("Getting full repo list\n");
  @repolist = @{&fetch_repolist($client)};
  foreach my $repo (sort(@repolist)) {
  	&debug("Found repo $repo\n");
  }
}
else {
  &debug("Using repo list from command line options: ".join(', ',@repolist)."\n");
}

# Go through each channel
foreach my $repo (sort(@repolist)) {
  chomp $repo;
  &debug("Getting errata from $repo\n");

  # Collect existing errata
  my @repoerrata = @{&fetch_repo_errata($client, $repo)};
  #chomp @repoerrata;
  foreach my $errata (@repoerrata) {
    &debug("Found existing errata for $errata\n");
    $existing{$errata} = 1;
  }

  # Get all packages in current channel
  my @allpkg = @{&fetch_repo_packages($client, $repo)};
  #chomp @allpkg;

  # Go through each package
  foreach my $arrayref (@allpkg) {
    my @arr = @{$arrayref};
    my $name = $arr[0];
    my $loc = $arr[1];
    &debug("Found package $name ($loc)\n");
    # Get the details of the current package
    $name2id{$loc} = $name;
    $name2channel{$loc} = $repo;
    $name2channel{$name} = $repo;
    $name2filename{$name} = $loc;
  }
}
&debug("\%name2id: " . Dumper(%name2id));
&debug("\%name2channel: " . Dumper(%name2channel));
&debug("\%name2filename " . Dumper(%name2filename));

##############################
# Process errata in XML file #
##############################

my @tasks = ();

# Go through each <errata>
foreach $advisory (sort(keys(%{$xml}))) {

  # Restore "proper" name of adivsory
  $advid = $advisory;
  $advid =~ s/--/:/;

  @packages = ();
  @channels = ();

  # Only consider CentOS (and Debian) errata
  unless($advisory =~ /^CE|^DSA/) { &debug("Skipping $advid\n"); next; }

  # Start processing
  &debug("Processing $advid\n");

  # Generate OVAL ID for security errata
  $ovalid = "";
  if ($advid =~ /CESA/) {
    if ($advid =~ /CESA-(\d+):(\d+)/) {
      $ovalid = "oval:com.redhat.rhsa:def:$1".sprintf("%04d", $2);
      &debug("Processing $advid -- OVAL ID is $ovalid\n");
    }
  }

  # Check if the errata already exists
  if (not(defined($existing{$advid}))) {
    # Errata does not exist yet
    &debug("Errata $advid does not exist yet\n");

    # Find package IDs mentioned in errata
    &find_packages($advisory);

    # Insert description from Red Hat OVAL file, if available (only for Security)
    if (defined($ovalid)) {
      if ( defined($rhsaxml->{definitions}->{definition}->{$ovalid}->{metadata}->{description}) ) {
        &debug("Using description from $ovalid\n");
        $xml->{$advisory}->{description} = $rhsaxml->{definitions}->{definition}->{$ovalid}->{metadata}->{description};
        # Remove Umlauts -- API throws errors if they are included
        $xml->{$advisory}->{description} = unidecode($xml->{$advisory}->{description});
        # Escape quotes in the description
        $xml->{$advisory}->{description} =~ s/\"/\\\"/g;
        $xml->{$advisory}->{description} =~ s/\Q\\"\E/\\\\\\\"/g;
      }
    }

    my %advisory_data = ();

    if (@packages >= 1) {
      # If there is at least one matching package create the errata?
      if ( ref($xml->{$advisory}->{packages}) eq 'ARRAY') {
        &info("Creating errata for $advid ($xml->{$advisory}->{synopsis}) (".($#packages +1)." of ".($#{$xml->{$advisory}->{packages}} +1).")\n");
      } else {
        &info("Creating errata for $advid ($xml->{$advisory}->{synopsis}) (1 of 1)\n");
      }

      $synopsis = $xml->{$advisory}->{synopsis};
      $synopsis =~ s/,/;/g;

      @{$advisory_data{'references'}} = ();
      foreach my $reference (split / +/, $xml->{$advisory}->{references}) {
	# https://access.redhat.com/errata/RHBA-2021:4487,Bug Fix Advisory,CEBA-2021:4487,CentOS xfsprogs Update
	my %refhash = (
		'href'  => $reference,
		'id'    => $advid,
		'title' => $synopsis,
		'type'  => $xml->{$advisory}->{type},
	);
	push @{$advisory_data{'references'}}, \%refhash;
      }

      #### Create package list file ####
      $advisory_data{'pkglist'}[0]{'name'} = 'collection-0';
      $advisory_data{'pkglist'}[0]{'shortname'} = '';
      # $advisory{'pkglist'}[0]{'module'} = nil;
      @{$advisory_data{'pkglist'}[0]{'packages'}} = ();
      foreach my $package (@packages) {

        # Escape plus signs in file names.
	my $filename = $package;
        $filename =~ s/\+/\\\+/g;

	&debug("package: $package");
        &debug("pulp-admin $pulp_args rpm repo content rpm --repo-id=$name2channel{$package} --match=\"filename=$filename\" --fields=name,version,release,epoch,arch,checksum,checksumtype | awk '{print \$2}");
        @pkgdetails = @{&fetch_repo_package($client, $name2channel{$package}, $filename)};
	&debug("pkgdetails is " . Dumper(\@pkgdetails) . "\n");
        my $rpm_filename = $name2filename{$package};
	my %packagehash = (
		'arch'              => $pkgdetails[4],
		'epoch'             => $pkgdetails[3],
		'filename'          => $rpm_filename,
		'name'              => $pkgdetails[0],
                #'reboot_suggested'  => false,
                #'relogin_suggested' => false,
                #'restart_suggested' => false,
		'release'           => $pkgdetails[2],
		#'sum'               => $pkgdetails[5],
		#'sum_type'          => $pkgdetails[6],
		'version'           => ''.$pkgdetails[1],
	);
        push @{ $advisory_data{'pkglist'}[0]{'packages'} }, \%packagehash;
      }
      #################################

      ####### Select correct type #####
    if($xml->{$advisory}->{type} eq "Security Advisory") {
      $type = "security";
      $severity = $xml->{$advisory}->{severity};
      ### Remove redundant severity update
      $title = $xml->{$advisory}->{synopsis};
      $title =~ s/$severity //g;
    }
    elsif($xml->{$advisory}->{type} eq "Bug Fix Advisory") {
      $type = "bugfix";
      $severity = "";
      $title = $xml->{$advisory}->{synopsis};
    }
    elsif($xml->{$advisory}->{type} eq "Product Enhancement Advisory") {
      $type = "enhancement";
      $severity = "";
      $title = $xml->{$advisory}->{synopsis};
    }
    else {
      $type = $xml->{$advisory}->{type};
    }
      #################################

      ####### Upload the errata #######
      my $reffile = '';
      my $packfile = '';
      #&debug("pulp-admin $pulp_args rpm repo uploads erratum --title=\"$title\" --description=\"$xml->{$advisory}->{description}\" --version=$xml->{$advisory}->{release} --release=\"$pkgdetails[5]\" --type=\"$type\" --severity=\"$severity\" --status=\"final\" --updated=\"$xml->{$advisory}->{issue_date}\" --issued=\"$xml->{$advisory}->{issue_date}\" --reference-csv=$reffile --pkglist-csv=$packfile --from=$xml->{$advisory}->{from} --repo-id=$name2channel{$packages[0]} --erratum-id=$advid");
      # title id severity issued_date type description reboot_suggested solution updated_date summary)
      $advisory_data{'title'}        = $title;
      $advisory_data{'summary'}      = $synopsis;
      $advisory_data{'description'}  = $xml->{$advisory}->{description};
      $advisory_data{'version'}      = 1; # $xml->{$advisory}->{release}; # ?
      $advisory_data{'release'}      = $pkgdetails[2]; # ?
      $advisory_data{'type'}         = $type;
      $advisory_data{'severity'}     = $severity;
      $advisory_data{'status'}       = 'final'; # ?
      $advisory_data{'updated_date'} = $xml->{$advisory}->{issue_date};
      $advisory_data{'issued_date'}  = $xml->{$advisory}->{issue_date};
      $advisory_data{'fromstr'}      = $xml->{$advisory}->{from}; # ?
      $advisory_data{'id'}           = $advid;
      #$result = `pulp-admin $pulp_args rpm repo uploads erratum --title="$title" --description="$xml->{$advisory}->{description}" --version=$xml->{$advisory}->{release} --release="$pkgdetails[5]" --type="$type" --severity="$severity" --status="final" --updated="$xml->{$advisory}->{issue_date}" --issued="$xml->{$advisory}->{issue_date}" --reference-csv=$reffile --pkglist-csv=$packfile --from=$xml->{$advisory}->{from} --repo-id=$name2channel{$packages[0]} --erratum-id=$advid`;
      my $repo_id = $name2channel{$packages[0]};
      # needs to be the base repo of /pulp/api/v3/repositories/rpm/rpm/d12345fe-e137-4b3d-9fef-b0097c21edd0/
      # not /pulp/api/v3/repositories/rpm/rpm/d12345fe-e137-4b3d-9fef-b0097c21edd0/versions/12/
      $repo_id =~ s-versions/\d+/$--;
      my $task_uri = &create_advisory($client, $repo_id, \%advisory_data);
      if (length($task_uri) > 0) {
      	push @tasks, $task_uri;
      }

      #&info("$result\n");
      #################################

    } else {
      # There is no related package so there is no errata created
      &notice("Skipping errata $advid ($xml->{$advisory}->{synopsis}) -- No packages found\n");
    }

  } else {
    &save_advisory($advid, $xml->{$advisory});
    &info("Errata for $advid already exists\n");
  }
}

sleep 10;

&notice("checking on status of tasks");
my %status = ();
foreach my $task_uri (@tasks) {
	my $json = $client->GET($task_uri)->responseContent();
	&debug("json: $json\n");
	my %hash = %{decode_json $json};
	my $state = $hash{'state'};
	if ($state ne 'completed') {
		&info("task not complete: " . $hash{'error'}{'description'});
		&debug("failed task: $json");
	}
	$status{$state}++;
}
my $str = '';
foreach my $k (keys %status) {
	$str .= "$k: " . $status{$k} . "\n";
}
&notice("task summary:\n$str");

exit;

# SUBS
sub debug() {
  if ($debug) {
    my $line = "DEBUG: @_";
    chomp $line;
    print $line,"\n";
  }
}

sub info() {
  if ($quiet) { return; }
  print "INFO: @_";
}

sub warning() {
  print "WARNING: @_";
}

sub error() {
  print "ERROR: @_";
}

sub notice() {
  if ($quiet) { return; }
  print "NOTICE: @_";
}

sub usage() {
  print "Usage: $0 --errata=<ERRATA-FILE> --host='https://foreman.example.com'\n";
  print "         [ --quiet | --debug ]\n";
  print "\n";
  print "REQUIRED:\n";
  print "  --errata\t\tThe XML file containing errata information\n";
  print "  --host\t\thost name of your smart proxy\n";
  print "\n";
  print "OPTIONAL\n";
  print "  --rhsa-oval\tOVAL XML file from Red Hat (recommended)\n";
  print "  --include-repo\tOnly consider packages and errata in the provided repositories. Can be provided multiple times\n";
  print "\n";
  print "LOGGING:\n";
  print "  --quiet\t\tOnly print warnings and errors\n";
  print "  --debug\t\tSet verbosity to debug (use this when reporting issues!)\n";
  print "\n";
}

sub eval_modules() {
  eval { require Text::Unidecode; };
  if ($@) { die "ERROR: You are missing Text::Unidecode\n       CentOS: yum install perl-Text-Unidecode\n"; };

  eval { require XML::Simple; };
  if ($@) { die "ERROR: You are missing XML::Simple\n       CentOS: yum install perl-XML-Simple\n"; };

  eval { require XML::Parser; };
  if ($@) { die "ERROR: You are missing XML::Parser\n       CentOS: yum install perl-XML-Parser\n"; };

  eval { require REST::Client; };
  if ($@) { die "ERROR: You are missing REST::Client\n       CentOS: yum install perl-REST-Client\n"; };

  eval { require JSON; };
  if ($@) { die "ERROR: You are missing JSON\n       CentOS: yum install perl-JSON\n"; };

  eval { require HTTP::Request::Common; };
  if ($@) { die "ERROR: You are missing HTTP::Request::Common\n       CentOS: yum install perl-HTTP-Message\n"; };
}

sub uniq() {
  my %all = ();
  @all{@_} = 1;
  return (keys %all);
}

sub find_packages() {
  #  INPUT: Advisory, e.g. CESA-2013:0123
  # OUTPUT: Array of Package IDs, Array of Channel Labels

  # Find package IDs mentioned in errata
  if ( ref($xml->{$_[0]}->{packages}) eq 'ARRAY') {
    foreach $package ( @{$xml->{$_[0]}->{packages}} ) {
      if (defined($name2id{$package})) {
        # We found it, nice
        &debug("Package: $package -> $name2id{$package} -> $name2channel{$package} \n");
        push(@packages, $name2id{$package});
        push(@channels, $name2channel{$package});
        # Ugly hack :)
        @packages = &uniq(@packages);
        @channels = &uniq(@channels);
       } else {
         # No such package, too bad
         &debug("Package: $package not found\n");
       }
     }
  } else {
    # errata has only one package
    if (defined($name2id{$xml->{$_[0]}->{packages}})) {
      # the one and only package is found
      &debug("Package: $xml->{$_[0]}->{packages} -> $name2id{$xml->{$_[0]}->{packages}} -> $name2channel{$xml->{$_[0]}->{packages}} \n");
      push(@packages, $name2id{$xml->{$_[0]}->{packages}});
      push(@channels, $name2channel{$xml->{$_[0]}->{packages}});
    } else {
      # no hit
      &debug("Package: $xml->{$_[0]}->{packages} not found\n");
    }
  }

}

sub fetch_results() {
	my ($client, $uri) = @_;
	my $json = $client->GET($uri)->responseContent();
	#&debug("json: $json\n");
	my $hashref = decode_json $json;
	my %hash = %{$hashref};
	return \@{$hash{'results'}};
}

sub fetch_results_field() {
	my ($client, $uri, $field) = @_;
	my @data = ();
	foreach my $hashref (@{&fetch_results($client, $uri)}) {
		my %h = %{$hashref};
		push @data, $h{$field};
	}
	return \@data;
}

sub fetch_results_fields() {
	my ($client, $uri, $arrayref) = @_;
	my @data = ();
	foreach my $hashref (@{&fetch_results($client, $uri)}) {
		my %h = %{$hashref};
		my @minidata = ();
		foreach my $field (@{$arrayref}) {
			push @minidata, $h{$field};
		}
		push @data, \@minidata;
	}
	return \@data;
}

# {
#   "pulp_href": "/pulp/api/v3/repositories/rpm/rpm/1616679f-1978-4904-994c-382df3899b4f/",
#   "pulp_created": "2021-10-14T22:13:15.793374Z",
#   "versions_href": "/pulp/api/v3/repositories/rpm/rpm/1616679f-1978-4904-994c-382df3899b4f/versions/",
#   "latest_version_href": "/pulp/api/v3/repositories/rpm/rpm/1616679f-1978-4904-994c-382df3899b4f/versions/0/",
#   "name": "ff53bc6f-8924-4803-a000-1fcc7789410e",
#   "description": "ff53bc6f-8924-4803-a000-1fcc7789410e",
#   "remote": null,
#   "metadata_signing_service": null,
#   "retain_package_versions": 0
# }
sub fetch_repolist() {
	my $client = shift;
	return &fetch_results_field($client, '/pulp/api/v3/repositories/rpm/rpm/', 'latest_version_href');
}

sub fetch_repo_errata() {
	my ($client, $href) = @_;
	return &fetch_results_field($client, "/pulp/api/v3/content/rpm/advisories/?repository_version=$href", 'id');
}

sub fetch_repo_packages() {
	my ($client, $href) = @_;
	my @data = ();
	my @fields = ('name', 'location_href');
	foreach my $arrayref (@{&fetch_results_fields($client, "/pulp/api/v3/content/rpm/packages/?repository_version=$href", \@fields)}) {
		my @arr = @{$arrayref};
		my @parts = split /\//, $arr[1];
		my $loc = pop @parts;
		my @newdata = ($arr[0], $loc); 
		push @data, \@newdata;
	}
	return \@data;
}

sub fetch_repo_package() {
	my ($client, $href, $filename) = @_;
	my @fields = split(/,/, 'name,version,release,epoch,arch,checksum,checksumtype');
	my @data = @{&fetch_results_fields($client, "/pulp/api/v3/content/rpm/packages/?repository_version=$href&name=$filename", \@fields)};
	return \@{$data[0]};
}

sub create_advisory() {
	my ($client, $repo_id, $hashref) = @_;
	my $uri = '/pulp/api/v3/content/rpm/advisories/';
	my $json = JSON->new;
	my $json_text = $json->encode($hashref);
	&debug("json_test=".$json_text);

	my %hash = %{$hashref};
	my $f = './new-advisories/' . $hash{'id'} . '.advisory';
	open(F, '>', $f) or die "can't open $f: $!\n";
	print F $json_text;
	close F;

	my $filename = $hash{'id'} . '.json';
	my $req = HTTP::Request::Common::POST(
		$uri,
		'Content-Type' => 'form-data',
		'Content' => {
			'repository' => $repo_id,
			'file' => [undef, $filename, 'Content-Type' => 'application/json', 'Content' => $json_text]
		},
	);
	&debug('request: ' . $req->headers->as_string . "\n" . $req->content);

	my %headers = %{$req->headers};
	my $resp = $client->POST($uri, $req->content, \%headers);
	my $code = $resp->responseCode();
	my $content = $resp->responseContent();
	my @rheaders = $resp->responseHeaders();
	my $str = '';
	foreach my $k (@rheaders) {
		$str .= "$k: " . $resp->responseHeader($k) . "\n";
	}
	&debug('response: ' . $code . ' ' . $content);
	&debug("response headers: $str");
	if ($code == 202) {
		my %taskinfo = %{decode_json $content};
		return $taskinfo{'task'};
	} else { return '' }
}

sub save_advisory() {
	my ($advid, $hashref) = @_;
	my $f = './old-advisories/' . $advid . '.advisory';
	open(F, '>', $f) or die "can't open $f: $!\n";
	print F Dumper($hashref);
	close F;
}
