$UiKit = '/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS5.1.sdk/System/Library/Frameworks/UIKit.framework/UIKit'

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
    target.should_receive(:symbols).any_number_of_times.and_return([])
  end
  target.stub(:vamap=)
  target.stub(:io).and_return(o[:io])
  target.stub(:publish_event)
  target
end

describe Indis::BinaryFormat::MachO do
  it "should parse mach-o header" do
    io = StringIO.new(File.open($UiKit, 'rb').read().force_encoding('BINARY'))
    target = macho_target_double(io: io)
    
    m = Indis::BinaryFormat::MachO.new(target, io)
    
    m.cputype.should == :CPU_TYPE_ARM
    m.cpusubtype.should == :CPU_SUBTYPE_ARM_V7
    m.filetype.should == :MH_DYLIB
    m.flags.should == [:MH_NOUNDEFS, :MH_DYLDLINK, :MH_TWOLEVEL, :MH_WEAK_DEFINES, :MH_BINDS_TO_WEAK, :MH_NO_REEXPORTED_DYLIBS]
  end
  
  it "should parse mach-o commands" do
    io = StringIO.new(File.open($UiKit, 'rb').read().force_encoding('BINARY'))
    target = macho_target_double(io: io)
    
    m = Indis::BinaryFormat::MachO.new(target, io)

    m.commands.length.should == 44
    c = m.commands.first
    c.cmd.should == :LC_SEGMENT
    c.class.should == Indis::MachO::SegmentCommand
    c.length.should == 668
    
    c.segname.should == '__TEXT'
    c.vmaddr.should == 0x00000000
    c.vmsize.should == 0x004a3000
    c.fileoff.should == 0
    c.filesize.should == 4861952
    c.maxprot.should == 0x00000005
    c.initprot.should == 0x00000005
    c.nsects.should == 9
    c.flags.should == 0x0
    
    c.sections.length.should == 9
    s = c.sections.first
    s.sectname.should == '__text'
    s.segname.should == '__TEXT'
  end
  
  it "should parse symbols" do
    sym = []
    io = StringIO.new(File.open($UiKit, 'rb').read().force_encoding('BINARY'))
    target = macho_target_double(io: io, symbols: sym)
    
    m = Indis::BinaryFormat::MachO.new(target, io)
    
    sym.length.should == 31746
  end
  
  it "should parse dyld operands" do
    io = StringIO.new(File.open($UiKit, 'rb').read().force_encoding('BINARY'))
    target = macho_target_double(io: io)
    
    m = Indis::BinaryFormat::MachO.new(target, io)
    dysymtab = m.commands.map{ |c| c if c.is_a?(Indis::MachO::DyldInfoOnlyCommand) }.compact.first
    dysymtab.bind_symbols.length.should == 10635
    dysymtab.weak_bind_symbols.length.should == 8
    dysymtab.lazy_bind_symbols.length.should == 991
  end
end