//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//


cplusplus {{
#include "INETDefs.h"
}}

enum itagType
{
    FLV_240p = 5;    // 'Low Quality, 240p, FLV, 400x240';
    ThreeGP_144p = 17;   // 'Low Quality, 144p, 3GP, 0x0';
    MP4_360p = 18;   // 'Medium Quality, 360p, MP4, 480x360';
    MP4_720p = 22;   // 'High Quality, 720p, MP4, 1280x720';
    FLV_360p = 34;   // 'Medium Quality, 360p, FLV, 640x360';
    FLV_480p = 35;   // 'Standard Definition, 480p, FLV, 854x480';
    ThreeGP_240p = 36;   // 'Low Quality, 240p, 3GP, 0x0';
    MP4_1080p = 37;  // 'Full High Quality, 1080p, MP4, 1920x1080';
    
};

packet YTRequestMsg
{
    int itag @enum(itagType);
    int dur;

}