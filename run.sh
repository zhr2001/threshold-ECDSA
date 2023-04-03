cd Setup && source /opt/intel/sgxsdk/environment && ./app > setuplog.txt &
# cd Setup && source /opt/intel/sgxsdk/environment && ./app &
sleep 1s
for i in {1..8}
do
    cd Node && source /opt/intel/sgxsdk/environment && ./app $i > log$i.txt &
done
