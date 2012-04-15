require 'indis-macho'

def macho_target_double(*args)
  o = args.length == 1 ? args[0] : {}
  
  target = double("Target")
  target.stub(:segments=)
  if o[:segments]
    target.should_receive(:segments){ o[:segments] }.any_number_of_times
  else
    target.should_receive(:segments).any_number_of_times.and_return([])
  end
  target.stub(:symbols=)
  if o[:symbols]
    target.should_receive(:symbols){ o[:symbols] }.any_number_of_times
  else
    target.should_receive(:symbols).any_number_of_times.and_return({})
  end
  target.stub(:vamap=)
  target.stub(:io).and_return(o[:io])
  target
end

describe Indis::BinaryFormat::MachO do
  it "should parse mach-o header" do
    io = StringIO.new(File.open('spec/fixtures/single-object.o', 'rb').read().force_encoding('BINARY'))
    target = macho_target_double(io: io)
    
    m = Indis::BinaryFormat::MachO.new(target, io)
    
    m.cputype.should == :CPU_TYPE_ARM
    m.cpusubtype.should == :CPU_SUBTYPE_ARM_V4T
    m.filetype.should == :MH_OBJECT
    m.flags.should == [:MH_SUBSECTIONS_VIA_SYMBOLS]
    
    io = StringIO.new(File.open('spec/fixtures/app-arm-release.o', 'rb').read().force_encoding('BINARY'))
    target = macho_target_double(io: io)
    
    m = Indis::BinaryFormat::MachO.new(target, io)
    
    m.cputype.should == :CPU_TYPE_ARM
    m.cpusubtype.should == :CPU_SUBTYPE_ARM_V7
    m.filetype.should == :MH_EXECUTE
    m.flags.should == [:MH_NOUNDEFS, :MH_DYLDLINK, :MH_TWOLEVEL, :MH_PIE]
  end
  
  it "should parse mach-o commands" do
    io = StringIO.new(File.open('spec/fixtures/single-object.o', 'rb').read().force_encoding('BINARY'))
    target = macho_target_double(io: io)
    
    m = Indis::BinaryFormat::MachO.new(target, io)

    m.commands.length.should == 3
    c = m.commands.first
    c.cmd.should == :LC_SEGMENT
    c.class.should == Indis::MachO::SegmentCommand
    c.length.should == 464
    
    c.segname.should == ''
    c.vmaddr.should == 0x0
    c.vmsize.should == 0x79
    c.fileoff.should == 596
    c.filesize.should == 121
    c.maxprot.should == 0x7
    c.initprot.should == 0x7
    c.nsects.should == 6
    c.flags.should == 0x0
    
    c.sections.length.should == 6
    s = c.sections.first
    s.sectname.should == '__text'
    s.segname.should == '__TEXT'
  end
  
  it "should parse stub segment from .o file" do
    seg = []
    
    io = StringIO.new(File.open('spec/fixtures/single-object.o', 'rb').read().force_encoding('BINARY'))
    target = macho_target_double(io: io, segments: seg)
    
    m = Indis::BinaryFormat::MachO.new(target, io)
    
    seg.length.should == 1
    seg[0].name.should == '__TEXT'
    seg[0].sections.length.should == 6
    seg[0].sections[0].name.should == '__text'
  end
  
  it "should parse symbols" do
    sym = {}
    io = StringIO.new(File.open('spec/fixtures/single-object.o', 'rb').read().force_encoding('BINARY'))
    target = macho_target_double(io: io, symbols: sym)
    
    m = Indis::BinaryFormat::MachO.new(target, io)
    
    sym.keys.should include("_add")
    sym.keys.should include("_sub")
    sym.keys.should include("_printf")
  end
end