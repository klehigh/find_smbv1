# Find SMBv1 activity.  
# Currently we only raise a notice, but will log the command in the future.
#
# Author: Keith Lehigh <klehigh@iu.edu>

module FindSMBv1;

export {
        redef enum Notice::Type += {
                Seen,
        };
}

# SMBv1 reply from server is most reliable way to find SMBv1 traffic
event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=-5
        {
        if ( !is_orig )
                {
		# suppress repeated notices involving any given pair of hosts
                NOTICE([$note=FindSMBv1::Seen,
                $msg=fmt("SMBv1 Connection %s to %s", c$id$orig_h, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$resp_h,c$id$orig_h)]);
                }
        }
