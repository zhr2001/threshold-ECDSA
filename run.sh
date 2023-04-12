cd Combiner && source /opt/intel/sgxsdk/environment && ./app > combiner.txt &

for i in {1..8}
do
    cd Node && source /opt/intel/sgxsdk/environment && ./app $i > log$i.txt &
    # cd Node && source /opt/intel/sgxsdk/environment && ./app $i &
done
