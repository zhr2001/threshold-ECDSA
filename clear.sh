killall -e "app"
for i in $(ipcs -m | grep -oh "0x[0-f]*")
do 
    if [ $i != "0x00000000" ]
    then
        ipcrm -M $i
    fi
done