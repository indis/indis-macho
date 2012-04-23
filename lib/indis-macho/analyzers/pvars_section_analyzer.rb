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

require "indis-core/data_entity"

module Indis
  module MachO
    class PVarsSectionAnalyzer
      def initialize(target)
        @target = target
        target.subscribe_for_event(:target_section_processed, self)
      end
      
      def target_section_processed(sect)
        return unless sect.name == '__program_vars'
        return unless sect.vmsize == 20
        e = DataEntity.new(sect.vmaddr+4*0, 4, @target.vmmap)
        e.tags[:meta] = 'ProgramVars.mh'
        @target.vmmap.map(e)
        e = DataEntity.new(sect.vmaddr+4*1, 4, @target.vmmap)
        e.tags[:meta] = 'ProgramVars.NXArgcPtr'
        @target.vmmap.map(e)
        e = DataEntity.new(sect.vmaddr+4*2, 4, @target.vmmap)
        e.tags[:meta] = 'ProgramVars.NXArgvPtr'
        @target.vmmap.map(e)
        e = DataEntity.new(sect.vmaddr+4*3, 4, @target.vmmap)
        e.tags[:meta] = 'ProgramVars.environPtr'
        @target.vmmap.map(e)
        e = DataEntity.new(sect.vmaddr+4*4, 4, @target.vmmap)
        e.tags[:meta] = 'ProgramVars.__prognamePtr'
        @target.vmmap.map(e)
      end
    end
  end
end