<?php
function returnBack($error)
{
    return response()->json([
        'status' => 'error',
        'message' => $error->getMessage()
    ], $error->getCode());
}

function getAllSettings()
{
    $group = 'site.settings.';
    $data = (object)[
        "general" => (object)[
            "site_name" => setting($group . 'general.site_name'),
            "site_logo" => setting($group . 'general.site_logo'),
            "site_favicon" => setting($group . 'general.site_favicon'),
            "footer_detail" => setting($group . 'general.footer_detail')
        ],
        "contact" => (object)[
            'phone' => setting($group . 'contact_info.phone'),
            'mail' => setting($group . 'contact_info.mail'),
            'address' => setting($group . 'contact_info.address')
        ],
        "newsletter" => (object)[
            "title" => setting($group . 'newsletter.title'),
            "text" => setting($group . 'newsletter.text')
        ],
        "backlink" => (object)[
            "qrcode" => setting($group . 'backlink.qrcode'),
            "facebook" => setting($group . 'backlink.facebook'),
            "instagram" => setting($group . 'backlink.instagram'),
            "linkedin" => setting($group . 'backlink.linkedin'),
            "youtube" => setting($group . 'backlink.youtube')
        ]
    ];
    return $data;
}
