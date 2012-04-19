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

require 'indis-core/symbol'

module Indis
  module MachO
    
    class Symbol < Indis::Symbol
      STAB_MASK = 0xe0
      PEXT_MASK = 0x10
      TYPE_MASK = 0x0e
      EXT_MASK = 0x01
      TYPE = {
        0x0 => :UNDEF,
        0x2 => :ABS,
        0xe => :SECT,
        0xc => :PBUD,
        0xa => :INDR,
      }
      STAB = {
        0x20 => :N_GSYM,    # global symbol
        0x22 => :N_FNAME,   # procedure name (f77 kludge)
        0x24 => :N_FUN,     # procedure name
        0x26 => :N_STSYM,   # static symbol
        0x28 => :N_LCSYM,   # .lcomm symbol
        0x2e => :N_BNSYM,   # begin nsect symbol
        0x3c => :N_OPT,     # emitted with gcc2_compiled and in gcc source
        0x40 => :N_RSYM,    # register symbol
        0x44 => :N_SLINE,   # src line
        0x4e => :N_ENSYM,   # end nsect symbol
        0x60 => :N_SSYM,    # structure elt
        0x64 => :N_SO,      # source file name
        0x66 => :N_OSO,     # object file name
        0x80 => :N_LSYM,    # local symbol
        0x82 => :N_BINCL,   # include file beginning
        0x84 => :N_SOL,     # #included file name
        0x86 => :N_PARAMS,  # compiler parameters
        0x88 => :N_VERSION, # compiler version
        0x8A => :N_OLEVEL,  # compiler -O level
        0xa0 => :N_PSYM,    # parameter
        0xa2 => :N_EINCL,   # include file end
        0xa4 => :N_ENTRY,   # alternate entry
        0xc0 => :N_LBRAC,   # left bracket
        0xc2 => :N_EXCL,    # deleted include file
        0xe0 => :N_RBRAC,   # right bracket
        0xe2 => :N_BCOMM,   # begin common
        0xe4 => :N_ECOMM,   # end common
        0xe8 => :N_ECOML,   # end common (local name)
        0xfe => :N_LENG,    # second stab entry with length information
      }
      REFERENCE_TYPE_MASK = 0xf
      DESC_REFERENCE = {
        0x0 => :REFERENCE_FLAG_UNDEFINED_NON_LAZY,
        0x1 => :REFERENCE_FLAG_UNDEFINED_LAZY,
        0x2 => :REFERENCE_FLAG_DEFINED,
        0x3 => :REFERENCE_FLAG_PRIVATE_DEFINED,
        0x4 => :REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY,
        0x5 => :REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY,
      }
      DESC_ADDITIONAL = {
        0x08 => :N_ARM_THUMB_DEF,
        0x10 => :REFERENCED_DYNAMICALLY,
        0x20 => :N_DESC_DISCARDED_OR_N_NO_DEAD_STRIP, # TODO: resolve mach file type
        0x40 => :N_WEAK_REF,
        0x80 => :N_WEAK_DEF,
      }
      LIBRARY_ORDINAL = {
        0x0  => :SELF_LIBRARY_ORDINAL,
        0xfe => :DYNAMIC_LOOKUP_ORDINAL,
        0xff => :EXECUTABLE_ORDINAL,
      }
      
      attr_writer :image, :section, :image, :vmaddr # image will be set later on by macho parser
      attr_reader :macho_section_index
      
      def initialize(payload, strtab)
        name_idx, @type_val, @macho_section_index, @desc_val, @value = payload.read(12).unpack('VCCSV')
        if name_idx == 0
          @name = ''
        else
          @name = strtab[name_idx..-1].split("\0", 2)[0]
        end
        
        super(@name, nil, nil, @value)
      end
      
      def type
        if stab?
          STAB[@type_val]
        else
          TYPE[@type_val & TYPE_MASK]
        end
      end
      
      def stab?
        @type_val & STAB_MASK != 0
      end
      
      def stab
        if stab?
          STAB[@type_val]
        else
          nil
        end
      end
      
      def private_extern?
        @type_val & PEXT_MASK == PEXT_MASK
      end
      
      def extern?
        @type_val & EXT_MASK == EXT_MASK
      end
      
      def desc
        d = [DESC_REFERENCE[@desc_val & REFERENCE_TYPE_MASK]]
        DESC_ADDITIONAL.each_pair do |k, v|
          d << v if @desc_val & k == k
        end
        d
      end
      
      def twolevel_library_ordinal
        lo = (@desc_val >> 8) & 0xff
        LIBRARY_ORDINAL[lo] || lo
      end
    end
    
  end
end