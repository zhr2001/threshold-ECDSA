cd Setup && source /opt/intel/sgxsdk/environment && ./app &
sleep 1s
for i in {1..11}
do
    cd Node && source /opt/intel/sgxsdk/environment && ./app $i &
    # echo $i
done
