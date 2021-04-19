@load base/frameworks/sumstats
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="res.all",$apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="res.404",$apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="uni.url.404",$apply=set(SumStats::UNIQUE));
    SumStats::create([$name="scan",
                      $epoch=10mins,
                      $reducers=set(r1,r2,r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local resall = result["res.all"];
                        local res404 = result["res.404"];
                        local uniurl = result["uni.url.404"];
                        if(res404$sum>2 && res404$sum/resall$sum>0.2)
						{
							if(uniurl$sum/res404$sum>0.5)
							{
								print fmt("%s is a scanner with %s scan attemps on %s urls",key$host,res404$sum,uniurl$unique);
							}
						}
                        }]);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    SumStats::observe("res.all", SumStats::Key($host=c$id$orig_h), SumStats::Observation());
    if ( code == 404 )
    {
    	SumStats::observe("res.404", SumStats::Key($host=c$id$orig_h), SumStats::Observation());
    	SumStats::observe("uni.url.404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
    }
