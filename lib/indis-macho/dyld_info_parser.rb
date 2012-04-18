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

require 'stringio'

module Indis
  module MachO
    
    class DyldInfoParser
      BIND_OPCODE_MASK    = 0xF0
      BIND_IMMEDIATE_MASK = 0x0F
      
      BIND_OPCODES = {
        0x00 => :BIND_OPCODE_DONE,
        0x10 => :BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
        0x20 => :BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
        0x30 => :BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
        0x40 => :BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
        0x50 => :BIND_OPCODE_SET_TYPE_IMM,
        0x60 => :BIND_OPCODE_SET_ADDEND_SLEB,
        0x70 => :BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB,
        0x80 => :BIND_OPCODE_ADD_ADDR_ULEB,
        0x90 => :BIND_OPCODE_DO_BIND,
        0xA0 => :BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
        0xB0 => :BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED,
        0xC0 => :BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB,
      }
      
      TYPE_IMM = {
        1 => :POINTER,
        2 => :TEXT_ABSOLUTE32,
        3 => :TEXT_PCREL32,
      }
      
      def initialize(bytes)
        @bytes = StringIO.new(bytes)
      end
      
      def parse
        syms = []
        sym = {offset: 0}
        begin
          
          b = pop
          opcode = BIND_OPCODES[b & BIND_OPCODE_MASK]
          imm = b & BIND_IMMEDIATE_MASK
          #puts "** OPCODE #{opcode} IMM #{imm}"
          case opcode
          when :BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
            sym[:library] = imm
          when :BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
            sym[:flags] = []
            sym[:flags] << :WEAK_IMPORT if imm & 1 == 1
            sym[:flags] << :NON_WEAK_DEFINITION if imm & 8 == 8
            
            nm = ''
            c = pop
            while c != 0 do
              nm += c.chr
              c = pop
            end
            sym[:name] = nm
          when :BIND_OPCODE_SET_TYPE_IMM
            #puts "Unknown type #{imm}" unless TYPE_IMM[imm]
            sym[:type] = TYPE_IMM[imm] || imm
          when :BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
            sym[:segment] = imm
            sym[:offset] = pop_uleb
          when :BIND_OPCODE_DONE
            #break
          when :BIND_OPCODE_DO_BIND
            syms << sym.dup
            sym[:offset] += 4
          when :BIND_OPCODE_ADD_ADDR_ULEB
            u = pop_uleb
            sym[:offset] += u
          when :BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
            syms << sym.dup
            sym[:offset] += 4 + imm*4
          when :BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
            count = pop_uleb
            skip  = pop_uleb
            count.times do
              syms << sym.dup
              sym[:offset] += skip + 4
            end
          else
            raise "unknown opcode #{opcode} #{(b & BIND_OPCODE_MASK).to_s 16}"
          end
          sym[:offset] &= 0xffffffff
        end while @bytes.pos < @bytes.length
        syms
      end
      
      private
      def pop
        @bytes.read(1).ord
      end
      
      def pop_uleb
        result = 0
        bit = 0
        begin
          p = pop
          slice = p & 0x7f
          result |= (slice << bit)
          bit += 7
        end while p & 0x80 != 0
        result
      end
    end
    
  end
end