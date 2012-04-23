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

require "indis-core/cstring_entity"

module Indis
  module MachO
    class StringsSectionAnalyzer
      def initialize(target)
        @target = target
        target.subscribe_for_event(:target_section_processed, self)
      end
      
      def target_section_processed(sect)
        return unless sect.type == :S_CSTRING_LITERALS
        adr = sect.vmaddr
        while adr < sect.vmaddr + sect.vmsize
          e = CStringEntity.new(adr, @target.vmmap)
          @target.vmmap.map!(e)
          adr += e.size
        end
      end
    end
  end
end