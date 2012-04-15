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

module Indis
  module MachO
    
    class Symbol
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
        0x20 => :N_GSYM,
        0x22 => :N_FNAME,
        0x24 => :N_FUN,
        0x26 => :N_STSYM,
        0x28 => :N_LCSYM,
        0x2e => :N_BNSYM,
        0x3c => :N_OPT,
        0x40 => :N_RSYM,
        0x44 => :N_SLINE,
        0x4e => :N_ENSYM,
        0x60 => :N_SSYM,
        0x64 => :N_SO,
        0x66 => :N_OSO,
        0x80 => :N_LSYM,
        0x82 => :N_BINCL,
        0x84 => :N_SOL,
        0x86 => :N_PARAMS,
        0x88 => :N_VERSION,
        0x8A => :N_OLEVEL,
        0xa0 => :N_PSYM,
        0xa2 => :N_EINCL,
        0xa4 => :N_ENTRY,
        0xc0 => :N_LBRAC,
        0xc2 => :N_EXCL,
        0xe0 => :N_RBRAC,
        0xe2 => :N_BCOMM,
        0xe4 => :N_ECOMM,
        0xe8 => :N_ECOML,
        0xfe => :N_LENG,
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
      
      attr_reader :name, :sect, :value
      
      def initialize(payload, strtab)
        name_idx, @type_val, @sect, @desc_val, @value = payload.read(12).unpack('VCCSV')
        if name_idx == 0
          @name = ''
        else
          @name = strtab[name_idx..-1].split("\0", 2)[0]
        end
        
        #puts "#{printf('%08x', value)} #{@name} sect #{@sect} #{self.type ? self.type : 'UNK 0b'+@type_val.to_s(2)} #{self.stab? ? 'stab ' : ''} #{self.private_extern? ? 'pvt ' : ''} #{self.extern? ? 'extern' : ''}"
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