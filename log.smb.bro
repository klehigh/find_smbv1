# log SMB Version activity.  Currently we only care about 
# SMBv1, but that could change in the future.
# Author: Keith Lehigh <klehigh@iu.edu>

module LogSMBVersion;

export {
        redef enum Notice::Type += {
                SMBv1_Seen,
        };
}

# SMBv1 reply from server is most reliable way to find SMBv1 traffic
event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=-5
        {
        if ( !is_orig )
                {
		# suppress repeated notices involving any given pair of hosts
                NOTICE([$note=LogSMBVersion::SMBv1_Seen,
                $msg=fmt("SMBv1 Connection %s to %s", c$id$orig_h, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$resp_h,c$id$orig_h)]);
                }
        }
