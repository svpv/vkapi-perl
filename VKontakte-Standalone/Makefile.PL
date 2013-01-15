use 5.008000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'VKontakte::API::Standalone',
    VERSION_FROM      => 'lib/VKontakte/Standalone.pm', # finds $VERSION
    PREREQ_PM         => {
        "WWW::Mechanize" => 0,
	"JSON" => 0,
	"URI" => 0,
	"Carp" => 0,
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/VKontakte/Standalone.pm', # retrieve abstract from module
       AUTHOR         => 'Krylov Ivan <krylov.r00t@gmail.com>') : ()),
);
