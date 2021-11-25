jQuery(document).ready(function($){
    
    // Register Session.
    $.ajax({
        url: OA_SINGLE_SIGN_ON_AJAX_GET_SSO_TOKEN, 
        method :'GET',
        dataType: 'json', 
        success: function(result)
        {console.log(OA_SINGLE_SIGN_ON_AJAX_GET_USER_NOTICE);
                console.log(result.val);
           	if (result.hasOwnProperty('val') && typeof result['val'] === 'string' && result['val'].length)
           	{

                // Check for existing session.
                if (result.val == 'check_session')
                {
                    console.log('check_session');
                    _oneall.push(['single_sign_on', 'do_check_for_sso_session', window.location.href, true]);                
                } 
                // Refresh current session.
                else
                {
                    if (result.val != 'no_token_found')
                    {
                        console.log('!= no_token_found  != check_session');
                        _oneall.push(['single_sign_on', 'do_register_sso_session', result.val]);
                    }
                }
        	}
        }
    });

    
    // Retrieve User Notices.
    $.ajax({
        url: OA_SINGLE_SIGN_ON_AJAX_GET_USER_NOTICE, 
        method :'GET',
        dataType: 'json', 
        success: function(result)
        {
            if (result.hasOwnProperty('val') && typeof result['val'] === 'string' && result['val'].length)
            {
                
                $('#single_sign_on_notice_container').html(result.val);
            }
        }
    });
});
