require 'indis-macho'

describe Indis::BinaryFormat do
  it "should autoload Mach-O format" do
    Indis::BinaryFormat.known_formats.should include(Indis::BinaryFormat::MachO)
  end
end