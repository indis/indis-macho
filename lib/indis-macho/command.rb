##############################################################################
#   Indis framework                                                          #
#   Copyright (C) 2012 Vladimir "Farcaller" Pouzanov <farcaller@gmail.com>   #
#                                                                            #
#   This program is free software: you can redistribute it and/or modify     #
#   it under the terms of the GNU General Public License as published by     #
#   the Free Software Foundation, either version 3 of the License, or        #
#   (at your option) any later version.                                      #
#                                                                            #
#   This program is distributed in the hope that it will be useful,          #
#   but WITHOUT ANY WARRANTY; without even the implied warranty of           #
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            #
#   GNU General Public License for more details.                             #
#                                                                            #
#   You should have received a copy of the GNU General Public License        #
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.    #
##############################################################################

require 'indis-macho/symbol'
require 'indis-macho/dyld_info_parser'

module Indis
  module MachO
    
    class UnknownCommandError < RuntimeError; end
    
    class Command
      LC_REQ_DYLD = 0x80000000
      
      CMD = {
        0x1 => :LC_SEGMENT,
        0x2 => :LC_SYMTAB,
        0x3 => :LC_SYMSEG,
        0x4 => :LC_THREAD,
        0x5 => :LC_UNIXTHREAD,
        0x6 => :LC_LOADFVMLIB,
        0x7 => :LC_IDFVMLIB,
        0x8 => :LC_IDENT,
        0x9 => :LC_FVMFILE,
        0xa => :LC_PREPAGE,
        0xb => :LC_DYSYMTAB,
        0xc => :LC_LOAD_DYLIB,
        0xd => :LC_ID_DYLIB,
        0xe => :LC_LOAD_DYLINKER,
        0xf => :LC_ID_DYLINKER,
        0x10 => :LC_PREBOUND_DYLIB,
        0x11 => :LC_ROUTINES,
        0x12 => :LC_SUB_FRAMEWORK,
        0x13 => :LC_SUB_UMBRELLA,
        0x14 => :LC_SUB_CLIENT,
        0x15 => :LC_SUB_LIBRARY,
        0x16 => :LC_TWOLEVEL_HINTS,
        0x17 => :LC_PREBIND_CKSUM,
        
        0x18 | LC_REQ_DYLD => :LC_LOAD_WEAK_DYLIB,
        0x19 => :LC_SEGMENT_64,
        0x1a => :LC_ROUTINES_64,
        0x1b => :LC_UUID,
        0x1c | LC_REQ_DYLD => :LC_RPATH,
        0x1d => :LC_CODE_SIGNATURE,
        0x1e => :LC_SEGMENT_SPLIT_INFO,
        0x1f | LC_REQ_DYLD => :LC_REEXPORT_DYLIB,
        0x20 => :LC_LAZY_LOAD_DYLIB,
        0x21 => :LC_ENCRYPTION_INFO,
        0x22 => :LC_DYLD_INFO,
        0x22|LC_REQ_DYLD => :LC_DYLD_INFO_ONLY,
        
        0x23 | LC_REQ_DYLD => :LC_LOAD_UPWARD_DYLIB,
        0x24 => :LC_VERSION_MIN_MACOSX,
        0x25 => :LC_VERSION_MIN_IPHONEOS,
        0x26 => :LC_FUNCTION_STARTS,
        0x27 => :LC_DYLD_ENVIRONMENT,
      }
      
      CMD_CLASS = {
        LC_SEGMENT: :SegmentCommand,
        LC_DYLD_INFO_ONLY: :DyldInfoOnlyCommand,
        LC_SYMTAB: :SymTabCommand,
        LC_DYSYMTAB: :DySymTabCommand,
        LC_LOAD_DYLINKER: :LoadDyLinkerCommand,
        LC_UUID: :UUIDCommand,
        LC_UNIXTHREAD: :ARMUnixThreadCommand,
        LC_ENCRYPTION_INFO: :EncryptionInfoCommand,
        LC_LOAD_DYLIB: :LoadDyLibCommand,
        LC_CODE_SIGNATURE: :CodeSignatureCommand,
        LC_VERSION_MIN_IPHONEOS: :VersionMinIPhoneOSCommand,
        LC_FUNCTION_STARTS: :FunctionStartsCommand,
      }
  
      attr_reader :cmd, :length
  
      def initialize(cmd, length, payload)
        @cmd = CMD[cmd]
        @length = length
        raise "Unknown mach-o command" unless @cmd
    
        process(payload)
      end
  
      def self.class_of_command(c)
        cmd = CMD[c]
        raise UnknownCommandError, "Unknown mach-o command #{c.to_s(16)}" unless cmd
        clsnm = CMD_CLASS[cmd]
        raise "Unsupported mach-o command #{c.to_s(16)} (#{cmd})" unless clsnm
        cls = Indis::MachO.const_get(clsnm)
      end
      
      private
      def process(payload)
        return unless self.class.fields
        self.class.fields.each do |f|
          case f[0]
          when :string
            s = payload.read(f[2]).strip.gsub("\0", "")
            instance_variable_set("@#{f[1]}".to_sym, s)
          when :uint32
            instance_variable_set("@#{f[1]}".to_sym, payload.read(4).unpack('V')[0])
          end
        end
      end
      
      def self.f_string(name, sz)
        @fields ||= []
        @fields << [:string, name, sz]
        attr_reader name.to_sym
      end
      
      def self.f_uint32(*names)
        @fields ||= []
        names.each do |nm|
          @fields << [:uint32, nm]
          attr_reader nm.to_sym
        end
      end
      
      def self.fields
        @fields
      end
    end
    
    class SectionSubCommand < Command # LC_SEGMENT.sub
      f_string :sectname, 16
      f_string :segname, 16
      f_uint32 :addr, :size, :offset, :align, :reloff, :nreloc, :flags, :reserved1, :reserved2
      attr_accessor :index
      attr_reader :type, :attributes
      
      SECTION_TYPE_MASK = 0x000000ff
      SECTION_ATTRIBUTES_MASK = 0xffffff00
      
      SECTION_TYPE = {
        0x00 => :S_REGULAR,                             # regular section
        0x01 => :S_ZEROFILL,                            # zero-fill on demand section
        0x02 => :S_CSTRING_LITERALS,                    # section with only literal C strings
        0x03 => :S_4BYTE_LITERALS,                      # section with only 4 byte literals
        0x04 => :S_8BYTE_LITERALS,                      # section with only 8 byte literals
        0x05 => :S_LITERAL_POINTERS,                    # section with only pointers to literals
        0x06 => :S_NON_LAZY_SYMBOL_POINTERS,            # section with only non-lazy symbol pointers
        0x07 => :S_LAZY_SYMBOL_POINTERS,                # section with only lazy symbol pointers
        0x08 => :S_SYMBOL_STUBS,                        # section with only symbol stubs (s.a. byte size of stub in the reserved2)
        0x09 => :S_MOD_INIT_FUNC_POINTERS,              # section with only function pointers for initialization
        0x0a => :S_MOD_TERM_FUNC_POINTERS,              # section with only function pointers for termination
        0x0b => :S_COALESCED,                           # section contains symbols that are to be coalesced
        0x0c => :S_GB_ZEROFILL,                         # zero fill on demand section (>4Gb)
        0x0d => :S_INTERPOSING,                         # section with only pairs of function pointers for interposing
        0x0e => :S_16BYTE_LITERALS,                     # section with only 16 byte literals
        0x0f => :S_DTRACE_DOF,                          # section contains DTrace Object Format
        0x10 => :S_LAZY_DYLIB_SYMBOL_POINTERS,          # section with only lazy symbol pointers to lazy loaded dylibs
        0x11 => :S_THREAD_LOCAL_REGULAR,                # template of initial values for TLVs
        0x12 => :S_THREAD_LOCAL_ZEROFILL,               # template of initial values for TLVs (zero-filled on demand?)
        0x13 => :S_THREAD_LOCAL_VARIABLES,              # TLV descriptors
        0x14 => :S_THREAD_LOCAL_VARIABLE_POINTERS,      # pointers to TLV descriptors
        0x15 => :S_THREAD_LOCAL_INIT_FUNCTION_POINTERS, # functions to call to initialize TLV values
      }
      
      SECTION_ATTRIBUTES = {
        0x80000000 => :S_ATTR_PURE_INSTRUCTIONS,   # section contains only true machine instructions
        0x40000000 => :S_ATTR_NO_TOC,              # section contains coalesced symbols that are not to be in a ranlib table of contents
        0x20000000 => :S_ATTR_STRIP_STATIC_SYMS,   # ok to strip static symbols in this section in files with the MH_DYLDLINK flag
        0x10000000 => :S_ATTR_NO_DEAD_STRIP,       # no dead stripping
        0x08000000 => :S_ATTR_LIVE_SUPPORT,        # blocks are live if they reference live blocks
        0x04000000 => :S_ATTR_SELF_MODIFYING_CODE, # Used with i386 code stubs written on by dyld
        # s.a. S_ATTR_DEBUG & friends in loader.h
      }
      
      def initialize(payload)
        process(payload)
        @type = SECTION_TYPE[@flags & SECTION_TYPE_MASK]
        atr = @falgs & SECTION_ATTRIBUTES_MASK
        @attributes = SECTION_ATTRIBUTES.map { |k,v| (atr & k == k) ? v : nil }.compact
      end
    end
    
    class SegmentCommand < Command # LC_SEGMENT
      f_string :segname, 16
      f_uint32 :vmaddr, :vmsize, :fileoff, :filesize, :maxprot, :initprot, :nsects, :flags
      attr_reader :sections
      
      def process(payload)
        super(payload)
        
        @sections = []
        @nsects.times do
          s = SectionSubCommand.new(payload)
          @sections << s
        end
      end
    end
    
    class SymTabCommand < Command # LC_SYMTAB
      f_uint32 :symoff, :nsyms, :stroff, :strsize
      attr_reader :symbols
      
      def process(payload)
        super(payload)
        
        pos = payload.pos
        
        payload.pos = @stroff
        strings = payload.read(@strsize)
        
        payload.pos = @symoff
        @symbols = []
        
        @nsyms.times do |n|
          s = Indis::MachO::Symbol.new(payload, strings)
          @symbols << s
        end
        payload.pos = pos
      end
    end
    
    class DySymTabCommand < Command # LC_DYSYMTAB
      f_uint32 :ilocalsym, :nlocalsym, :iextdefsym, :nextdefsym, :iundefsym, :nundefsym, :tocoff,
               :ntoc, :modtaboff, :nmodtab, :extrefsymoff, :nextrefsyms, :indirectsymoff, :nindirectsyms,
               :extreloff, :nextrel, :locreloff, :nlocrel
    end
    
    class LoadDyLinkerCommand < Command # LC_LOAD_DYLINKER
      attr_reader :name
      
      def process(payload)
        super(payload)
        @name = payload.read(@length-8).strip
      end
    end
    
    class UUIDCommand < Command # LC_UUID
      attr_reader :UUID
      
      def process(payload)
        super(payload)
        @UUID = payload.read(16)
      end
    end
    
    class ARMUnixThreadCommand < Command # LC_UNIXTHREAD
      REGISTERS = [:r0, :r1, :r2, :r3, :r4, :r5, :r6, :r7, :r8, :r9, :r10, :r11, :r12, :sp, :lr, :pc, :cpsr]
      f_uint32 :flavor, :count
      attr_reader :registers
      
      def process(payload)
        super(payload)
        # XXX: this one parses only ARM thread state, need to get back to mach-o header to know the flavor
        
        @registers = payload.read(4*17).unpack('V'*17)
      end
    end
    
    class EncryptionInfoCommand < Command # LC_ENCRYPTION_INFO
      f_uint32 :cryptoff, :cryptsize, :cryptid
    end
    
    class LoadDyLibCommand < Command # LC_LOAD_DYLIB
      attr_reader :name, :timestamp, :current_version, :compatibility_version
      
      def process(payload)
        super(payload)
        
        ofs_to_name = payload.read(4).unpack('V')[0]
        
        @timestamp, @current_version, @compatibility_version = payload.read(4*3).unpack('VVV')
        
        name_sz = @length - ofs_to_name - 4*3 + 8 + 4
        @name = payload.read(name_sz).strip
      end
    end
    
    class CodeSignatureCommand < Command # LC_CODE_SIGNATURE
      f_uint32 :dataoff, :datasize
    end
    
    class VersionMinIPhoneOSCommand < Command # LC_VERSION_MIN_IPHONEOS
      attr_reader :version, :sdk
      
      def process(payload)
        v, s = payload.read(8).unpack('VV')
        
        @version = "#{(v & 0xffff0000) >> 16}.#{(v & 0xff00) >> 8}.#{v & 0xff}"
        @sdk = s
      end
    end
    
    class FunctionStartsCommand < Command # LC_FUNCTION_STARTS
      f_uint32 :dataoff, :datasize
    end
    
    class DyldInfoOnlyCommand < Command # LC_DYLD_INFO_ONLY
      f_uint32 :rebase_off, :rebase_size, :bind_off, :bind_size, :weak_bind_off, :weak_bind_size,
               :lazy_bind_off, :lazy_bind_size, :export_off, :export_size
      attr_reader :bind_symbols, :weak_bind_symbols, :lazy_bind_symbols
     
      def process(payload)
        super(payload)
        
        # TODO: rebase
        
        off = payload.pos
        payload.pos = @bind_off
        bind = payload.read(@bind_size)
        @bind_symbols = DyldInfoParser.new(bind).parse if @bind_size > 0
        
        payload.pos = @weak_bind_off
        weak_bind = payload.read(@weak_bind_size)
        @weak_bind_symbols = DyldInfoParser.new(weak_bind).parse if @weak_bind_size > 0
        
        payload.pos = @lazy_bind_off
        lazy_bind = payload.read(@lazy_bind_size)
        @lazy_bind_symbols = DyldInfoParser.new(lazy_bind).parse if @lazy_bind_size > 0
        
        # TODO: export
        
        payload.pos = off
      end
    end
  
  end
end