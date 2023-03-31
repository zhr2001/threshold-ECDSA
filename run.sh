cd Setup && source /opt/intel/sgxsdk/environment && ./app > setuplog.txt &
sleep 1s
for i in {1..9}
do
    cd Node && source /opt/intel/sgxsdk/environment && ./app $i > log$i.txt &

    # echo $i
done
