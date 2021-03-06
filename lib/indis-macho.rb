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

require 'indis-core/binary_architecture'
require 'indis-core/binary_format'
require 'indis-core/segment'
require 'indis-core/section'
require 'indis-core/symbol'
require 'indis-macho/version'
require 'indis-macho/command'
require 'indis-macho/symbol'

require 'indis-macho/analyzers/strings_section_analyzer'
require 'indis-macho/analyzers/pvars_section_analyzer'

module Indis
  module BinaryFormat
    
    class MachO < Format
      MH_MAGIC = 0xfeedface
      
      CPUARCH = {
        :CPU_TYPE_ARM => :arm,
      }
      
      CPUTYPE = {
        12 => :CPU_TYPE_ARM
      }

      CPUSUBTYPE = {
        5 => :CPU_SUBTYPE_ARM_V4T,
        6 => :CPU_SUBTYPE_ARM_V6,
        7 => :CPU_SUBTYPE_ARM_V5TEJ,
        8 => :CPU_SUBTYPE_ARM_XSCALE,
        9 => :CPU_SUBTYPE_ARM_V7
      }

      FILETYPE = {
        0x1 => :MH_OBJECT,
        0x2 => :MH_EXECUTE,
        0x3 => :MH_FVMLIB,
        0x4 => :MH_CORE,
        0x5 => :MH_PRELOAD,
        0x6 => :MH_DYLIB,
        0x7 => :MH_DYLINKER,
        0x8 => :MH_BUNDLE,
        0x9 => :MH_DYLIB_STUB,
        0xa => :MH_DSYM,
        0xb => :MH_KEXT_BUNDLE
      }

      FLAGS = {
        0x1 => :MH_NOUNDEFS,
        0x2 => :MH_INCRLINK,
        0x4 => :MH_DYLDLINK,
        0x8 => :MH_BINDATLOAD,
        0x10 => :MH_PREBOUND,
        0x20 => :MH_SPLIT_SEGS,
        0x40 => :MH_LAZY_INIT,
        0x80 => :MH_TWOLEVEL,
        0x100 => :MH_FORCE_FLAT,
        0x200 => :MH_NOMULTIDEFS,
        0x400 => :MH_NOFIXPREBINDING,
        0x800 => :MH_PREBINDABLE,
        0x1000 => :MH_ALLMODSBOUND,
        0x2000 => :MH_SUBSECTIONS_VIA_SYMBOLS,
        0x4000 => :MH_CANONICAL,
        0x8000 => :MH_WEAK_DEFINES,
        0x10000 => :MH_BINDS_TO_WEAK,
        0x20000 => :MH_ALLOW_STACK_EXECUTION,
        0x40000 => :MH_ROOT_SAFE,
        0x80000 => :MH_SETUID_SAFE,
        0x100000 => :MH_NO_REEXPORTED_DYLIBS,
        0x200000 => :MH_PIE,
        0x400000 => :MH_DEAD_STRIPPABLE_DYLIB,
        0x800000 => :MH_HAS_TLV_DESCRIPTORS,
        0x1000000 => :MH_NO_HEAP_EXECUTION,
      }
      
      attr_reader :cputype, :cpusubtype, :filetype, :commands, :architecture
      
      def self.magic
        MH_MAGIC
      end
      
      def self.name
        'Mach-O'
      end
      
      def initialize(target, io)
        super(target, io)
        
        @commands = []

        parse_header
        parse_commands

        build_segments
        build_dylibs if self.flags.include? :MH_TWOLEVEL
        build_symbols
        build_indirect_symbols
      end
      
      def flags
        unless @flags
          @flags = []
          FLAGS.each_pair do |k, v|
            @flags << v if @flags_val & k == k
          end
        end
        @flags
      end
      
      def resolve_symbol_at_address(vmaddr)
        segcommands = @commands.map{ |c| c if c.is_a?(Indis::MachO::SegmentCommand) }.compact
        seg = segcommands.find { |seg| vmaddr >= seg.vmaddr && vmaddr < seg.vmaddr+seg.vmsize }
        return nil unless seg
        
        ok_types = [:S_NON_LAZY_SYMBOL_POINTERS, :S_LAZY_SYMBOL_POINTERS, :S_LAZY_DYLIB_SYMBOL_POINTERS,
                    :S_THREAD_LOCAL_VARIABLE_POINTERS, :S_SYMBOL_STUBS]
        sect = seg.sections.find { |sec| vmaddr >= sec.addr && vmaddr < sec.addr+sec.size && ok_types.include?(sec.type) }
        return nil unless sect
        
        stride = sect.type == :S_SYMBOL_STUBS ? sect.reserved2 : 4 # cctools/otool/ofile_print.c:8105
        index = sect.reserved1 + (vmaddr - sect.addr) / stride
        
        return nil if index >= @indirect_symbols.length
        
        symb = @symbols[@indirect_symbols[index]]
        return nil unless symb
        symb.vmaddr = vmaddr
        @target.publish_event(:macho_indirect_symbol_resolved, vmaddr, symb)
        symb
      end
      
      private
      def validate_format
        raise "Not a Mach-O" if @io.length < 4
        magic = @io.read(4).unpack('V')[0]
        raise "Bad magic" unless magic == MH_MAGIC
        @io.seek(-4, IO::SEEK_CUR)          
      end
      
      def parse_header
        validate_format
        
        @magic, @cputype, @cpusubtype, @filetype, @ncmds, @sizeofcmds, @flags_val = @io.read(7*4).unpack('VVVVVVV')

        @cputype = CPUTYPE[@cputype]
        raise "Unknown CPU type" unless @cputype

        @cpusubtype = CPUSUBTYPE[@cpusubtype]
        raise "Unknown CPU subtype" unless @cpusubtype

        @filetype = FILETYPE[@filetype]
        raise "Unknown file type" unless @filetype

        @architecture = CPUARCH[@cputype]
      end
      
      def parse_commands
        @ncmds.times do
          cmd, size = @io.read(2*4).unpack('VV')

          begin
            c = Indis::MachO::Command.class_of_command(cmd).new(cmd, size, @io)
            @commands << c
            @target.publish_event(:macho_command_processed, c)
          rescue Indis::MachO::UnknownCommandError
            print "Unknown command #{cmd} size #{size}, skipping\n"
            @io.read(size-8)
          end
        end
      end
      
      def build_segments
        @indexed_sections = [nil]
        segcommands = @commands.map{ |c| c if c.is_a?(Indis::MachO::SegmentCommand) }.compact
        
        @target.segments = []
        
        pos = @target.io.pos
        segcommands.each do |cmd|
          name = if cmd.segname.length > 0
            cmd.segname
          else
            if cmd.sections.length > 0 && cmd.sections.first.segname.length > 0
              cmd.sections.first.segname
            else
              name = '*NONAME*'
            end
          end
          
          @target.io.pos = cmd.fileoff
          seg = Indis::Segment.new(@target, name, cmd.vmaddr, cmd.vmsize, cmd.fileoff, @target.io.read(cmd.filesize))
          @target.segments << seg
          @target.publish_event(:target_segment_processed, seg)
          
          cmd.sections.each do |sec|
            sec.index = @indexed_sections.length
            s = Indis::Section.new(seg, sec.sectname, sec.addr, sec.size, sec.offset, sec.type, sec.attributes)
            seg.sections << s
            @target.publish_event(:target_section_processed, s)
            @indexed_sections << s
          end
        end
        @target.io.pos = pos
      end
      
      def build_dylibs
        @indexed_dylibs = [nil]
        dylibcommands = @commands.map{ |c| c if c.is_a?(Indis::MachO::LoadDyLibCommand) }.compact
        
        dylibcommands.each do |dy|
          @indexed_dylibs << dy.name
        end
      end
      
      def build_symbols
        symtabcommand = @commands.find{ |c| c.is_a?(Indis::MachO::SymTabCommand) }
        return if symtabcommand.length == 0
        
        @symbols = symtabcommand.symbols
        
        @target.symbols = []
        
        symtabcommand.symbols.each do |sym|
          next if sym.stab?
          
          sym.section = @indexed_sections[sym.macho_section_index] if sym.macho_section_index > 0
          
          sym.image = if self.flags.include? :MH_TWOLEVEL
            l2 = sym.twolevel_library_ordinal
            @indexed_dylibs[l2] if l2.is_a?(Fixnum)
          end
          
          @target.symbols << sym
          @target.publish_event(:target_symbol_processed, sym)
        end
      end
      
      def build_indirect_symbols
        dysymtabcommand = @commands.find{ |c| c.is_a?(Indis::MachO::DySymTabCommand) }
        return if !dysymtabcommand || dysymtabcommand.length == 0
        
        @indirect_symbols = dysymtabcommand.indirect_symbols
      end
    end
    
  end
end
