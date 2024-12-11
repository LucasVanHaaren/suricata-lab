
set datafile separator ","
set terminal png size 800,600
set output 'analysis_summary.png'

set title "Suricata Analysis Summary"
set xlabel "Subfolder"
set ylabel "Count"
set grid

set style data linespoints

plot "analysis_summary.csv" using 2:xtic(1) title "Alerts" with linespoints, \
     "analysis_summary.csv" using 3:xtic(1) title "Filestore files" with linespoints, \
     "analysis_summary.csv" using 4:xtic(1) title "Protocol transactions" with linespoints