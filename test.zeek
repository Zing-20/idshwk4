@load base/frameworks/sumstats

event http_reply (c: connection, version: string, code: count, reason: string)
{
	SumStats::observe("res.all", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
	if(code==404)
	{
		SumStats::observe("res.404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
		SumStats::observe("uni.url.404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
	}
}

event zeek_init()
{
	
	local r1=SumStats::Reducer($stream="res.all", $apply=set(SumStats::SUM)); 
	local r2=SumStats::Reducer($stream="res.404", $apply=set(SumStats::SUM));
	local r3=SumStats::Reducer($stream="uni.url.404", $apply=set(SumStats::UNIQUE));
	
	SumStats::create([$name="scanner",
		$epoch=10min, 
		$reducers=set(r1,r2,r3), 
		$epoch_result(ts:time, key: SumStats::Key, result: SumStats::Result)=
		{
		local s1=result["res.all"]; 
		local s2=result["res.404"]; 
		local s3=result["uni.url.404"];
		if (s2$sum>2 && 1.0*s2$sum/s1$sum>0.2 && 1.0*s3$unique/s2$sum>0.5)
		{
			print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, s2$sum, s3$unique);
		}
		}]);
}
